package pcloudbinary

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/rclone/rclone/backend/pcloud/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/oauthutil"
)

// Client exposes the pcloud binary API.
type Client interface {
	Exec(ctx context.Context, req *BinaryRequest, resp api.ResultWithError) error
	Close(ctx context.Context) error
}

type client struct {
	server string
	ts     *oauthutil.TokenSource
	pacer  *fs.Pacer

	mu          sync.Mutex
	conn        *tls.Conn
	isConnected bool
}

// NewClient creates a new pcloud binary API client.
func NewClient(server string, ts *oauthutil.TokenSource, pacer *fs.Pacer) Client {
	return &client{
		ts:     ts,
		pacer:  pacer,
		server: server,
	}
}

// Close closes the underlying connection.
func (c *client) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("close conn: %w", err)
	}
	c.isConnected = false
	c.conn = nil
	return nil
}

// Exec marshalls the request, executes it, unmarshals the response and returns it.
func (c *client) Exec(ctx context.Context, req *BinaryRequest, resp api.ResultWithError) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isConnected {
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:8399", c.server), nil)
		if err != nil {
			return fmt.Errorf("establish connection: %w", err)
		}
		c.conn = conn
		c.isConnected = true
	}

	token, err := c.ts.Token()
	if err != nil {
		return fmt.Errorf("get current token: %w", err)
	}
	req.StringParam("access_token", token.AccessToken)
	reqBytes, err := req.Marshal()
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	fs.Debugf(nil, "request %s (%d): %v %v %v\n", req.Method, req.DataLen, req.StringParams, req.NumParams, req.BoolParams)

	return c.pacer.Call(func() (bool, error) {
		n, err := c.conn.Write(reqBytes)
		if err != nil {
			return false, fmt.Errorf("send request: %w", err)
		}
		if n != len(reqBytes) {
			return false, fmt.Errorf("send request: expected %d sent, acutal sent %d", len(reqBytes), n)
		}
		if req.DataLen > 0 {
			if req.Data == nil {
				return false, fmt.Errorf("reqest has %d DataLen but no data", req.DataLen)
			}
			dataWritten, err := io.Copy(c.conn, req.Data)
			if err != nil {
				return false, fmt.Errorf("send data: %w", err)
			}
			if req.DataLen != uint64(dataWritten) {
				return false, fmt.Errorf("send data: expected %d sent, acutal sent %d", req.DataLen, dataWritten)
			}
		}

		respSizeBytes := make([]byte, 4)
		_, err = c.conn.Read(respSizeBytes)
		if err != nil {
			return false, fmt.Errorf("read response size: %w", err)
		}
		respSize := binary.LittleEndian.Uint32(respSizeBytes)
		respBytes := make([]byte, respSize)
		_, err = io.ReadFull(c.conn, respBytes)
		if err != nil {
			return false, fmt.Errorf("receive response: %w", err)
		}
		respBytes = append(respSizeBytes, respBytes...)
		if err := Unmarshal(respBytes, resp); err != nil {
			return false, fmt.Errorf("unmarshal response: %w", err)
		}
		if err := errorHandler(resp.GetError()); err != nil {
			return false, err
		}
		if dataResponse, ok := resp.(api.ResultWithData); ok {
			n, err := dataResponse.ReadFrom(c.conn)
			if err != nil {
				return false, fmt.Errorf("read data: %w", err)
			}
			fs.Debugf(nil, "data response (%d)", n)
			return false, nil
		}
		fs.Debugf(nil, "response %+v", resp)
		return false, nil
	})
}

// errorHandler parses a non 2xx error response into an error
func errorHandler(err api.Error) error {
	if err.Result != 0 || err.ErrorString != "" {
		return fmt.Errorf("error response: %w", &err)
	}
	return nil
}
