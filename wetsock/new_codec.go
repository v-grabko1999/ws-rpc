package wetsock

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
)

// NewEndpoint створює Endpoint для WebSocket з увімкненим шифруванням
func NewEndpoint(registry *wsrpc.Registry, ws *websocket.Conn, keyString string) (*wsrpc.Endpoint, error) {
	c, err := NewCodec(ws, keyString)
	if err != nil {
		return nil, err
	}
	e := wsrpc.NewEndpoint(c, registry)
	return e, nil
}

// ----------------------------------------------------------------------------
// Фабрика для створення зашифрованого codec
// ----------------------------------------------------------------------------

func NewCodec(ws *websocket.Conn, keyString string) (*codec, error) {
	// Перевірка довжини ключа
	key := []byte(keyString)
	if len(key) != LenSecretKey {
		return nil, errors.New("ключ повинен мати 32 байти довжини (AES-256)")
	}

	block, gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}

	c := &codec{
		WS:            ws,
		sendChan:      make(chan []byte, SendChanLen),
		heartbeatDone: make(chan struct{}),
		block:         block,
		gcm:           gcm,
	}

	// Горутіна для відправки зашифрованих повідомлень
	go c.sendLoop()
	// Горутіна для PING/PONG
	go c.startHeartbeat()

	return c, nil
}

func newAESGCM(key []byte) (cipher.Block, cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return block, gcm, nil
}
