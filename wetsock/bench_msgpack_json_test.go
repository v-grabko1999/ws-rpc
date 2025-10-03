package wetsock_test

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/vmihailenco/msgpack/v5"
)

// Ініціалізація RNG для генерації тестових даних
func init() { rand.Seed(time.Now().UnixNano()) }

// ---------------- Допоміжні генератори ----------------

func genBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// Невелике типове RPC-повідомлення
func smallMessage() *wsrpc.Message {
	return &wsrpc.Message{
		ID:     uint64(rand.Uint32()),
		Func:   "Inventory.GetItems",
		Args:   map[string]interface{}{"loc": "UA-1", "filter": "active"},
		Result: nil,
		Error:  nil,
		Pad:    "",
	}
}

// Велике повідомлення з бінарним payload у Result
func largeMessage(size int) *wsrpc.Message {
	return &wsrpc.Message{
		ID:     uint64(rand.Uint32()),
		Func:   "Files.UploadChunk",
		Args:   nil,
		Result: genBytes(size), // ВАЖЛИВО: []byte всередині interface{}
		Error:  nil,
		Pad:    "",
	}
}

// ---------------- JSON: малі ----------------

func BenchmarkJSON_Small_Marshal(b *testing.B) {
	msg := smallMessage()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSON_Small_Unmarshal(b *testing.B) {
	msg := smallMessage()
	raw, _ := json.Marshal(msg)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var dst wsrpc.Message
		if err := json.Unmarshal(raw, &dst); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------- JSON: великі (включно з 100MB) ----------------

func BenchmarkJSON_Large_Marshal_1MB(b *testing.B)   { benchJSONLargeMarshal(b, 1<<20) }
func BenchmarkJSON_Large_Marshal_10MB(b *testing.B)  { benchJSONLargeMarshal(b, 10<<20) }
func BenchmarkJSON_Large_Marshal_100MB(b *testing.B) { benchJSONLargeMarshal(b, 100<<20) }

func benchJSONLargeMarshal(b *testing.B, size int) {
	msg := largeMessage(size)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSON_Large_Unmarshal_1MB(b *testing.B)   { benchJSONLargeUnmarshal(b, 1<<20) }
func BenchmarkJSON_Large_Unmarshal_10MB(b *testing.B)  { benchJSONLargeUnmarshal(b, 10<<20) }
func BenchmarkJSON_Large_Unmarshal_100MB(b *testing.B) { benchJSONLargeUnmarshal(b, 100<<20) }

func benchJSONLargeUnmarshal(b *testing.B, size int) {
	msg := largeMessage(size)
	raw, _ := json.Marshal(msg)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var dst wsrpc.Message
		if err := json.Unmarshal(raw, &dst); err != nil {
			b.Fatal(err)
		}

		// JSON кодує []byte як base64-рядок, назад у interface{} приходить string
		switch v := dst.Result.(type) {
		case string:
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				b.Fatal(err)
			}
			if len(decoded) != size {
				b.Fatalf("unexpected size: got %d want %d", len(decoded), size)
			}
		case []byte:
			if len(v) != size {
				b.Fatalf("unexpected size: got %d want %d", len(v), size)
			}
		case nil:
			b.Fatal("nil result after unmarshal")
		default:
			b.Fatalf("unexpected type for Result: %T", v)
		}
	}
}

// ---------------- MessagePack: малі ----------------

func BenchmarkMsgpack_Small_Marshal(b *testing.B) {
	msg := smallMessage()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := msgpack.Marshal(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMsgpack_Small_Unmarshal(b *testing.B) {
	msg := smallMessage()
	raw, _ := msgpack.Marshal(msg)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var dst wsrpc.Message
		if err := msgpack.Unmarshal(raw, &dst); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------- MessagePack: великі (включно з 100MB) ----------------

func BenchmarkMsgpack_Large_Marshal_1MB(b *testing.B)   { benchMsgpackLargeMarshal(b, 1<<20) }
func BenchmarkMsgpack_Large_Marshal_10MB(b *testing.B)  { benchMsgpackLargeMarshal(b, 10<<20) }
func BenchmarkMsgpack_Large_Marshal_100MB(b *testing.B) { benchMsgpackLargeMarshal(b, 100<<20) }

func benchMsgpackLargeMarshal(b *testing.B, size int) {
	msg := largeMessage(size)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := msgpack.Marshal(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMsgpack_Large_Unmarshal_1MB(b *testing.B)   { benchMsgpackLargeUnmarshal(b, 1<<20) }
func BenchmarkMsgpack_Large_Unmarshal_10MB(b *testing.B)  { benchMsgpackLargeUnmarshal(b, 10<<20) }
func BenchmarkMsgpack_Large_Unmarshal_100MB(b *testing.B) { benchMsgpackLargeUnmarshal(b, 100<<20) }

func benchMsgpackLargeUnmarshal(b *testing.B, size int) {
	msg := largeMessage(size)
	raw, _ := msgpack.Marshal(msg)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var dst wsrpc.Message
		if err := msgpack.Unmarshal(raw, &dst); err != nil {
			b.Fatal(err)
		}
		// Для msgpack []byte залишаються []byte
		v, ok := dst.Result.([]byte)
		if !ok {
			b.Fatalf("unexpected type for Result: %T", dst.Result)
		}
		if len(v) != size {
			b.Fatalf("unexpected size: got %d want %d", len(v), size)
		}
	}
}

// ---------------- Додатково: roundtrip на малих ----------------

func BenchmarkJSON_Small_Roundtrip(b *testing.B) {
	msg := smallMessage()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		raw, err := json.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
		var dst wsrpc.Message
		if err := json.Unmarshal(raw, &dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMsgpack_Small_Roundtrip(b *testing.B) {
	msg := smallMessage()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		raw, err := msgpack.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
		var dst wsrpc.Message
		if err := msgpack.Unmarshal(raw, &dst); err != nil {
			b.Fatal(err)
		}
	}
}
