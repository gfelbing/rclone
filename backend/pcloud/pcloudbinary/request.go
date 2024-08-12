package pcloudbinary

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

type BinaryRequest struct {
	Method       string
	StringParams map[string]string
	NumParams    map[string]uint64
	BoolParams   map[string]bool
	DataLen      uint64
	Data         io.Reader
}

func NewRequest(method string) *BinaryRequest {
	return &BinaryRequest{
		Method: method,
	}
}

func (r *BinaryRequest) StringParam(key string, value string) {
	if r.StringParams == nil {
		r.StringParams = map[string]string{}
	}
	r.StringParams[key] = value
}

func (r *BinaryRequest) DateTimeParam(key string, value time.Time) {
	strValue := value.Format(timeFormat)
	r.StringParam(key, strValue)
}

func (r *BinaryRequest) NumParam(key string, value uint64) {
	if r.NumParams == nil {
		r.NumParams = map[string]uint64{}
	}
	r.NumParams[key] = value
}

func (r *BinaryRequest) Marshal() ([]byte, error) {
	out := []byte{0, 0}
	requestLen := uint16(2)

	// byte0 0: method_len (0-6), has_data (7)
	methodLen := byte(len(r.Method))
	if r.Data != nil {
		methodLen = methodLen | 128
	}
	//out := []byte{(methodLen << 1) | hasData}
	out = append(out, methodLen)
	requestLen = requestLen + 1

	// if data present, next byte 1-8 are data len
	if r.Data != nil {
		dataLen := make([]byte, 8)
		binary.LittleEndian.PutUint64(dataLen, r.DataLen)
		out = append(out, dataLen...)
		requestLen = requestLen + 8
	}

	// next method_len bytes are name of the method
	out = append(out, []byte(r.Method)...)
	requestLen = requestLen + uint16(len(r.Method))

	// next byte contains number of arguments
	numArgs := byte(len(r.StringParams) + len(r.NumParams) + len(r.BoolParams))
	out = append(out, numArgs)
	requestLen = requestLen + 1

	// string parameters
	for name, value := range r.StringParams {
		// name_len (0-5), type (6-7: 00 string, 01 number, 10 bool)
		out = append(out, byte(len(name)))
		requestLen = requestLen + 1
		// name of parameter
		out = append(out, []byte(name)...)
		requestLen = requestLen + uint16(len(name))
		// 4 byte length
		valueLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(valueLen, uint32(len(value)))
		out = append(out, valueLen...)
		requestLen = requestLen + 4
		// string content
		out = append(out, []byte(value)...)
		requestLen = requestLen + uint16(len(value))
	}
	// number parameters
	for name, value := range r.NumParams {
		// name_len (0-5), type (6-7: 00 string, 01 number, 10 bool)
		out = append(out, byte(len(name)|64))
		requestLen = requestLen + 1
		// name of parameter
		out = append(out, []byte(name)...)
		requestLen = requestLen + uint16(len(name))
		// 8 bytes value
		valueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueBytes, value)
		out = append(out, valueBytes...)
		requestLen = requestLen + 8
	}
	// bool parameters
	for name, value := range r.BoolParams {
		// name_len (0-5), type (6-7: 00 string, 01 number, 10 bool)
		out = append(out, byte(len(name)|128))
		requestLen = requestLen + 1
		// name of parameter
		out = append(out, []byte(name)...)
		requestLen = requestLen + uint16(len(name))
		// 8 bytes value
		valueByte := byte(0)
		if value {
			valueByte = 1
		}
		out = append(out, valueByte)
		requestLen = requestLen + 1
	}

	binary.LittleEndian.PutUint16(out[0:2], requestLen-2)

	return out, nil
}

func (req *BinaryRequest) Read(b []byte) (n int64, err error) {
	reqLen := binary.LittleEndian.Uint16(b[0:2])
	n = n + 2

	methodLen := b[n] & 127
	hasData := b[n] >= 128
	n = n + 1

	dataLen := uint64(0)
	if hasData {
		dataLen = binary.LittleEndian.Uint64(b[n : n+8])
		n = n + 8
	}
	totalLen := dataLen + uint64(reqLen) + 2
	if totalLen != uint64(len(b)) {
		return n, fmt.Errorf("expected %d (2/%d/%d) bytes, got %d", totalLen, reqLen, dataLen, len(b))
	}

	req.Method = string(b[n : n+int64(methodLen)])
	n = n + int64(methodLen)

	numArgs := b[n]
	n = n + 1

	for i := 0; i < int(numArgs); i++ {
		nameLen := b[n] & 31
		paramType := b[n] >> 6
		n = n + 1

		name := string(b[n : n+int64(nameLen)])
		n = n + int64(nameLen)

		if paramType == 0 {
			// string
			if req.StringParams == nil {
				req.StringParams = map[string]string{}
			}

			valueLen := binary.LittleEndian.Uint32(b[n : n+4])
			n = n + 4
			value := string(b[n : n+int64(valueLen)])
			n = n + int64(valueLen)
			req.StringParams[name] = value
			continue
		}
		if paramType == 1 {
			// number
			if req.NumParams == nil {
				req.NumParams = map[string]uint64{}
			}

			value := binary.LittleEndian.Uint64(b[n : n+8])
			n = n + 8
			req.NumParams[name] = value
			continue
		}
		if paramType == 2 {
			// number
			if req.BoolParams == nil {
				req.BoolParams = map[string]bool{}
			}

			req.BoolParams[name] = b[n] != 0
			n = n + 1
		}
	}

	return n, err
}
