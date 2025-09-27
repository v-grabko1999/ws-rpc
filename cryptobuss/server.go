package cryptobuss

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

// ServerCfg містить приватний підписний ключ сервера та ідентифікатор ключа (keyID).
// SignPriv має бути повним ed25519.PrivateKey (64 байти), KeyID — рядок для ротації.
type ServerCfg struct {
	SignPriv ed25519.PrivateKey
	KeyID    string

	OnRegistry func(reg *wsrpc.Registry) error
	OnEndpoint func(*wsrpc.Endpoint) error
}

// --------------------------- Інтеграція в Server/Client --------------------

// Server тепер вимагає ServerCfg (тут передається підписний ключ і keyID).
// fn — реєстрація сервісів у registry; fnEnd — що робити з endpoint після створення.
func Server(cfg *ServerCfg, w http.ResponseWriter, r *http.Request) error {
	if cfg == nil || cfg.SignPriv == nil || len(cfg.SignPriv) == 0 || cfg.KeyID == "" {
		return errors.New("server config incomplete: SignPriv and KeyID required")
	}

	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	// Виконуємо handshake до створення endpoint
	sessionKey, err := performServerHandshake(conn, cfg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}
	if len(sessionKey) != 32 {
		conn.Close()
		return fmt.Errorf("sessionKey length invalid: %d", len(sessionKey))
	}

	registry := wsrpc.NewRegistry()
	if err := cfg.OnRegistry(registry); err != nil {
		conn.Close()
		return err
	}

	endpoint, err := wetsock.NewEndpoint(registry, conn, string(sessionKey))
	if err != nil {
		conn.Close()
		return err
	}

	return cfg.OnEndpoint(endpoint)
}
