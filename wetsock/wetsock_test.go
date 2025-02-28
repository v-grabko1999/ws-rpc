package wetsock_test

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gorilla/websocket"

	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

func TestCodec_ReadMessage(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()

		msg := wsrpc.Message{
			ID:     1,
			Func:   "TestFunction",
			Args:   json.RawMessage(`{"param":"value"}`),
			Result: nil,
			Error:  nil,
		}
		if err := conn.WriteJSON(msg); err != nil {
			t.Fatalf("Failed to write JSON: %v", err)
		}
	}))
	defer s.Close()

	wsURL := "ws" + s.URL[4:]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	codec := wetsock.NewCodec(conn)
	var msg wsrpc.Message
	if err := codec.ReadMessage(&msg); err != nil {
		t.Fatalf("Failed to read message: %v", err)
	}

	if msg.ID != 1 || msg.Func != "TestFunction" {
		t.Errorf("Unexpected message content: %+v", msg)
	}
}

func TestCodec_WriteMessage(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()

		var msg wsrpc.Message
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("Failed to read JSON: %v", err)
		}

		if msg.ID != 1 || msg.Func != "TestFunction" {
			t.Errorf("Unexpected message content: %+v", msg)
		}
	}))
	defer s.Close()

	wsURL := "ws" + s.URL[4:]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	codec := wetsock.NewCodec(conn)
	msg := wsrpc.Message{
		ID:   1,
		Func: "TestFunction",
	}
	if err := codec.WriteMessage(&msg); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}
}

func TestCodec_UnmarshalArgs(t *testing.T) {
	codec := wetsock.NewCodec(nil)
	msg := &wsrpc.Message{Args: json.RawMessage(`{"param":"value"}`)}
	var args map[string]string

	if err := codec.UnmarshalArgs(msg, &args); err != nil {
		t.Fatalf("Failed to unmarshal args: %v", err)
	}

	if args["param"] != "value" {
		t.Errorf("Unexpected args content: %+v", args)
	}
}
func TestCodec_UnmarshalResult(t *testing.T) {
	codec := wetsock.NewCodec(nil)
	msg := &wsrpc.Message{Result: json.RawMessage(`{"response":"success"}`)}
	var result map[string]string

	if err := codec.UnmarshalResult(msg, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if result["response"] != "success" {
		t.Errorf("Unexpected result content: %+v", result)
	}
}
func TestCodec_Close(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()
	}))
	defer s.Close()

	wsURL := "ws" + s.URL[4:]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	codec := wetsock.NewCodec(conn)

	if err := codec.Close(); err != nil {
		t.Fatalf("Failed to close codec: %v", err)
	}
}

func TestCodec_FillArgs(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()
	}))
	defer s.Close()

	wsURL := "ws" + s.URL[4:]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	codec := wetsock.NewCodec(conn)
	argList := []reflect.Value{reflect.ValueOf((*websocket.Conn)(nil))}
	codec.FillArgs(argList)

	if argList[0].Interface() != conn {
		t.Errorf("Expected filled argument to be the websocket connection, got: %v", argList[0])
	}
}

func TestOneShotListener(t *testing.T) {
	server, client := net.Pipe()
	listener := wetsock.NewOneShotListener(server)

	// Test Accept()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Unexpected error on Accept: %v", err)
	}
	if conn != server {
		t.Fatalf("Unexpected connection returned from Accept")
	}

	// Second Accept() should return EOF
	_, err = listener.Accept()
	if err != io.EOF {
		t.Fatalf("Expected EOF, got: %v", err)
	}

	// Test Addr()
	if listener.Addr() != server.LocalAddr() {
		t.Fatalf("Unexpected Addr() result")
	}

	// Test Close()
	// Test Close()
	listener.Close()
	if !listener.IsClosed() {
		t.Fatalf("Listener should be closed")
	}

	client.Close()
}
