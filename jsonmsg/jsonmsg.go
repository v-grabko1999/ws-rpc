package jsonmsg

import (
	"encoding/json"
	"errors"
	"io"
	"sync"

	wsrpc "github.com/v-grabko1999/ws-rpc"
)

type codec struct {
	dec     *json.Decoder
	sending sync.Mutex
	enc     *json.Encoder
	closer  io.Closer
}

// This is ugly, but i need to override the unmarshaling logic for
// Args and Result, or they'll end up as map[string]interface{}.
// Perhaps some day encoding/json will support embedded structs, and I
// can embed wsrpc.Message and just override the two fields I need to
// change.
type jsonMessage struct {
	ID     uint64          `json:"id,string,omitempty"`
	Func   string          `json:"fn,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wsrpc.Error    `json:"error,omitempty"`
}

func (c *codec) ReadMessage(msg *wsrpc.Message) error {
	var jm jsonMessage
	err := c.dec.Decode(&jm)
	if err != nil {
		return err
	}
	msg.ID = jm.ID
	msg.Func = jm.Func
	msg.Args = jm.Args
	msg.Result = jm.Result
	msg.Error = jm.Error
	return nil
}

func (c *codec) WriteMessage(msg *wsrpc.Message) error {
	c.sending.Lock()
	defer c.sending.Unlock()
	return c.enc.Encode(msg)
}

func (c *codec) Close() error {
	return c.closer.Close()
}

func (c *codec) UnmarshalArgs(msg *wsrpc.Message, args interface{}) error {
	raw := msg.Args.(json.RawMessage)
	if raw == nil {
		return nil
	}
	err := json.Unmarshal(raw, args)
	return err
}

func (c *codec) UnmarshalResult(msg *wsrpc.Message, result interface{}) error {
	raw := msg.Result.(json.RawMessage)
	if raw == nil {
		return errors.New("wsrpc.jsonmsg response must set result")
	}
	err := json.Unmarshal(raw, result)
	return err
}

func NewCodec(conn io.ReadWriteCloser) *codec {
	c := &codec{
		dec:    json.NewDecoder(conn),
		enc:    json.NewEncoder(conn),
		closer: conn,
	}
	return c
}
