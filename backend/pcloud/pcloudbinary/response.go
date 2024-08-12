package pcloudbinary

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/pcloud/api"
	"github.com/rclone/rclone/fs"
)

const timeFormat = time.RFC1123Z

var NegativeNumberParam = fmt.Errorf("pcloud doesn't support negative number parameters. use string param instead.")

type stringIndex struct {
	Index map[int]string
}

type reverseIndex struct {
	Index map[string]int
}

// Marshal marshalls a pcloud binary response into byte array, ready for transfer.
func Marshal(v any) ([]byte, error) {
	marshalled, err := marshalValue(reflect.ValueOf(v), &reverseIndex{Index: map[string]int{}})
	if err != nil {
		return nil, fmt.Errorf("marshalling value: %w", err)
	}
	outBytes := make([]byte, 4+len(marshalled))
	binary.LittleEndian.PutUint32(outBytes[0:4], uint32(len(marshalled)))
	copy(outBytes[4:], marshalled)
	return outBytes, nil
}

func marshalValue(rValue reflect.Value, strIndex *reverseIndex) ([]byte, error) {
	rValue = reflect.Indirect(rValue)
	switch rValue.Kind() {
	case reflect.String:
		r, err := marshalString(rValue.String(), strIndex)
		return r, err
	case reflect.Uint64:
		return marshalUint(rValue.Uint())
	case reflect.Int:
		v := rValue.Int()
		if v < 0 {
			return nil, NegativeNumberParam
		}
		return marshalUint(uint64(v))
	case reflect.Int64:
		v := rValue.Int()
		if v < 0 {
			return nil, NegativeNumberParam
		}
		r, err := marshalUint(uint64(v))
		return r, err
	case reflect.Bool:
		return marshalBool(rValue.Bool())
	case reflect.Slice:
		out := []byte{17}
		for idx := 0; idx < rValue.Len(); idx++ {
			newOut, err := marshalValue(rValue.Index(idx), strIndex)
			if err != nil {
				return nil, fmt.Errorf("write array: %w", err)
			}
			out = append(out, newOut...)
		}
		return append(out, 255), nil
	case reflect.Map:
		out := []byte{16}
		iter := reflect.ValueOf(rValue).MapRange()
		for iter.Next() {
			keyOut, err := marshalValue(iter.Key(), strIndex)
			if err != nil {
				return nil, fmt.Errorf("write map key: %w", err)
			}
			valueOut, err := marshalValue(iter.Value(), strIndex)
			if err != nil {
				return nil, fmt.Errorf("write map value: %w", err)
			}
			out = append(append(out, keyOut...), valueOut...)
		}
		return append(out, 255), nil
	case reflect.Struct:
		rType := rValue.Type()
		if rType == reflect.TypeOf(api.Time{}) {
			timeString := rValue.MethodByName("Format").Call([]reflect.Value{reflect.ValueOf(timeFormat)})[0].String()
			return marshalString(timeString, strIndex)
		}
		out := []byte{16}
		fields := getAllFields(rType)
		times := map[string][]byte{}
		for _, fieldType := range fields {
			fieldValue := rValue.FieldByName(fieldType.Name)
			if fieldValue.IsZero() {
				continue
			}
			tag := fieldType.Tag.Get("json")
			if tag == "" {
				continue
			}
			key := strings.Split(tag, ",")[0]
			keyOut, err := marshalString(key, strIndex)
			if err != nil {
				return nil, fmt.Errorf("write struct key: %w", err)
			}
			valueOut, err := marshalValue(fieldValue, strIndex)
			if err != nil {
				return nil, fmt.Errorf("write struct value: %w", err)
			}
			if isTime(fieldValue) {
				// undocumented "feature":
				// special case for datetimes: if the value is equal to another timestamp in the struct, reuse it by referencing the key
				existing, ok := times[string(valueOut)]
				if ok {
					valueOut = existing
				} else {
					times[string(valueOut)] = keyOut
				}
			}
			out = append(append(out, keyOut...), valueOut...)
		}
		return append(out, 255), nil
	}
	return nil, fmt.Errorf("unknown value type %s", rValue)
}

func getAllFields(rType reflect.Type) []reflect.StructField {
	res := []reflect.StructField{}
	for f := 0; f < rType.NumField(); f++ {
		field := rType.Field(f)
		if field.Anonymous {
			res = append(res, getAllFields(field.Type)...)
			continue
		}
		res = append(res, field)
	}
	return res
}

func marshalUint(v uint64) ([]byte, error) {
	out := []byte{8}
	for valueType := 8; v > 0; valueType++ {
		out[0] = byte(valueType)
		out = append(out, byte(v))
		v = v >> 8
	}
	return out, nil
}

func marshalBool(v bool) ([]byte, error) {
	valueType := byte(18)
	if v {
		valueType = 19
	}
	return []byte{valueType}, nil
}

func marshalString(v string, strIndex *reverseIndex) ([]byte, error) {
	idx, ok := strIndex.Index[v]
	if ok {
		// reuse string
		if idx < 49 {
			return []byte{byte(idx) + 150}, nil
		}
		out := []byte{4}
		for valueType := 4; idx > 0; valueType++ {
			out[0] = byte(valueType)
			out = append(out, byte(idx))
			idx = idx >> 8
		}
		return out, nil
	}
	strIndex.Index[v] = len(strIndex.Index)
	if len(v) < 49 {
		valueType := byte(100 + len(v))
		return append([]byte{valueType}, []byte(v)...), nil
	}
	out := []byte{0}
	strLen := len(v)
	for valueType := 0; strLen > 0; valueType++ {
		out[0] = byte(valueType)
		out = append(out, byte(strLen))
		strLen = strLen >> 8
	}
	return append(out, []byte(v)...), nil
}

// Unmarshal unmarshalls a pcloud binary response into the supplied v
func Unmarshal(data []byte, v any) error {
	msgLen := binary.LittleEndian.Uint32(data[0:4])
	actualLen := uint32(len(data[4:]))
	if actualLen != msgLen {
		return fmt.Errorf("expected len %d, got %d", msgLen, actualLen)
	}
	rValue := reflect.ValueOf(v)
	parsed, _, err := unmarshalValue(data[4:], &stringIndex{Index: map[int]string{}})
	fs.Debugf(nil, "parsed response: %v", parsed)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return reflectInto(rValue, parsed, map[string]api.Time{})
}

func isTime(rValue reflect.Value) bool {
	return rValue.Type() == reflect.TypeOf(api.Time{})
}

func reflectInto(rValue reflect.Value, parsed any, timeRefs map[string]api.Time) error {
	rValue = reflect.Indirect(rValue)
	if isTime(rValue) {
		parsedString, ok := parsed.(string)
		if !ok {
			return fmt.Errorf("response was not a string, cannot unmarshal into time: %v", parsed)
		}
		newT, err := time.Parse(timeFormat, parsedString)
		if err != nil {
			// sometimes pcloud writes garbage into datetime fields. ignoring.
			return nil
		}
		rValue.Set(reflect.ValueOf(api.Time(newT)))
		return nil
	}
	switch rValue.Kind() {
	case reflect.Struct:
		parsedMap, ok := parsed.(map[string]any)
		if !ok {
			return fmt.Errorf("response was not a map, cannot unmarshal into struct (%s): %v", rValue.Type(), parsed)
		}
		rStruct := rValue.Type()
		for i := 0; i < rStruct.NumField(); i++ {
			rField := rStruct.Field(i)
			if rField.Anonymous {
				if err := reflectInto(rValue.FieldByName(rField.Name), parsedMap, timeRefs); err != nil {
					return err
				}
				continue
			}
			key := strings.Split(rField.Tag.Get("json"), ",")[0]
			value, ok := parsedMap[key]
			if !ok {
				continue
			}
			rFieldValue := reflect.Indirect(rValue.FieldByName(rField.Name))
			if isTime(rFieldValue) {
				// undocumented "feature":
				// special case for datetimes: if the value is equal to another timestamp in the struct, reuse it by referencing the key
				valueString, ok := value.(string)
				if !ok {
					return fmt.Errorf("response was not a string, cannot unmarshal into time: %v", parsed)
				}
				if referedValue, ok := timeRefs[valueString]; ok {
					rFieldValue.Set(reflect.ValueOf(referedValue))
				} else {
					newT, err := time.Parse(timeFormat, valueString)
					if err != nil {
						// sometimes pcloud writes garbage into datetime fields. ignoring.
						return nil
					}
					timeRefs[key] = api.Time(newT)
					rFieldValue.Set(reflect.ValueOf(api.Time(newT)))
				}
				continue
			}
			if err := reflectInto(rFieldValue, value, timeRefs); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice:
		parsedSlice, ok := parsed.([]any)
		if !ok {
			return fmt.Errorf("response was not an array, cannot unmarshal into slice: %v", parsed)
		}
		rValue.Grow(len(parsedSlice))
		for _, elem := range parsedSlice {
			elemType := rValue.Type().Elem()
			elemValue := reflect.Indirect(reflect.New(elemType))
			if err := reflectInto(elemValue, elem, timeRefs); err != nil {
				return err
			}
			rValue.Set(reflect.Append(rValue, elemValue))
		}
		return nil
	case reflect.Map:
		rValue.Set(reflect.ValueOf(parsed))
		return nil
	case reflect.Uint64:
		rValue.Set(reflect.ValueOf(parsed))
		return nil
	case reflect.Bool:
		rValue.Set(reflect.ValueOf(parsed))
		return nil
	case reflect.String:
		rValue.Set(reflect.ValueOf(parsed))
		return nil
	case reflect.Int64:
		uint64 := reflect.ValueOf(parsed).Uint()
		rValue.Set(reflect.ValueOf(int64(uint64)))
		return nil
	case reflect.Int:
		uint64 := reflect.ValueOf(parsed).Uint()
		rValue.Set(reflect.ValueOf(int(uint64)))
		return nil
	}
	return fmt.Errorf("unknown value type %s", rValue)
}

// UnmarshalJSON turns JSON into a Time
func unmarshalTime(data []byte, t *time.Time) error {
	newT, err := time.Parse(timeFormat, string(data))
	if err != nil {
		return err
	}
	*t = newT
	return nil
}

func unmarshalValue(b []byte, strIndex *stringIndex) (value any, n int64, err error) {
	valueType := b[n]
	n = n + 1
	// string: 1-4 byte length, n byte string
	if valueType <= 3 {
		strLen := uint32(b[n])
		n = n + 1
		for i := 0; i < int(valueType); i++ {
			strLen = strLen | uint32(b[n])<<i
			n = n + 1
		}
		str := string(b[n : n+int64(strLen)])
		n = n + int64(strLen)
		strIndex.Index[len(strIndex.Index)] = str
		return str, n, err
	}
	// short string types
	if valueType >= 100 && valueType <= 149 {
		strLen := valueType - 100
		if int64(len(b)) < n+int64(strLen) {
			return "", n, fmt.Errorf("type %d: expected %d bytes, got %d", valueType, n+int64(strLen), len(b))
		}
		str := string(b[n : n+int64(strLen)])
		n = n + int64(strLen)
		strIndex.Index[len(strIndex.Index)] = str
		return str, n, err
	}
	// reused string types, 1-4 byte index
	if valueType >= 4 && valueType <= 7 {
		strID := uint32(b[n])
		n = n + 1
		for i := 0; i < int(valueType)-4; i++ {
			strID = strID | uint32(b[n])<<i
			n = n + 1
		}
		str, ok := strIndex.Index[int(strID)]
		if !ok {
			return "", n, fmt.Errorf("no reusable string with id %d", strID)
		}
		return str, n, err
	}
	// reused string types, index encoded in type
	if valueType >= 150 && valueType <= 199 {
		strID := valueType - 150
		str, ok := strIndex.Index[int(strID)]
		if !ok {
			return "", n, fmt.Errorf("no reusable string with id %d", strID)
		}
		return str, n, err
	}
	// number types, 1-8 byte
	if valueType >= 8 && valueType <= 15 {
		number := uint64(b[n])
		n = n + 1
		for i := 1; i <= int(valueType)-8; i++ {
			number = number | uint64(b[n])<<(i*8)
			n = n + 1
		}
		return number, n, err
	}
	// short number types, directly encoded in type
	if valueType >= 200 && valueType <= 219 {
		number := valueType - 200
		return uint64(number), n, err
	}
	// bool types
	if valueType >= 18 && valueType <= 19 {
		return valueType == 19, n, err
	}
	// array types
	if valueType == 17 {
		result := []any{}
		for {
			nextType := b[n]
			if nextType == 255 {
				n = n + 1
				return result, n, err
			}
			nextValue, nextN, err := unmarshalValue(b[n:], strIndex)
			n = n + nextN
			if err != nil {
				return nil, n, fmt.Errorf("read array: %w", err)
			}
			result = append(result, nextValue)
		}
	}
	// hash (mapped) types
	if valueType == 16 {
		result := map[string]any{}
		for {
			nextType := b[n]
			if nextType == 255 {
				n = n + 1
				return result, n, err
			}
			key, nextN, err := unmarshalValue(b[n:], strIndex)
			keyStr, ok := key.(string)
			if !ok {
				return nil, n, fmt.Errorf("key of map is not a string")
			}
			n = n + nextN
			if err != nil {
				return nil, n, fmt.Errorf("read key of map: %w", err)
			}
			value, nextN, err := unmarshalValue(b[n:], strIndex)
			n = n + nextN
			if err != nil {
				return nil, n, fmt.Errorf("read value of map: %w", err)
			}
			result[keyStr] = value
		}
	}
	// data type
	if valueType == 20 {
		dataLen := binary.LittleEndian.Uint64(b[n : n+8])
		n = n + 8
		return dataLen, n, nil
		/*
			data := b[n : n+int64(dataLen)]
			n = n + int64(dataLen)
			return data, n, err
		*/
	}
	return nil, n, fmt.Errorf("unknown value type %d", valueType)
}
