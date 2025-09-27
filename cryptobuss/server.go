package cryptobuss

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

// ServerCfg містить приватний підписний ключ сервера та ідентифікатор ключа (keyID).
type ServerCfg struct {
	SignPriv ed25519.PrivateKey
	KeyID    string

	OnRegistry func(reg *wsrpc.Registry) error
	OnEndpoint func(*wsrpc.Endpoint) error
}

// Server виконує websocket-апгрейд, крипто-handshake, створює Endpoint і САМ запускає Serve().
// OnEndpoint викликається вже після створення endpoint (і після старту Serve()),
// тож у колбеку НЕ потрібно викликати Serve() вдруге.
func Server(cfg *ServerCfg, w http.ResponseWriter, r *http.Request) error {
	if cfg == nil || cfg.SignPriv == nil || len(cfg.SignPriv) == 0 || cfg.KeyID == "" {
		return errors.New("server config incomplete: SignPriv and KeyID required")
	}

	upgrader := websocket.Upgrader{
		// Щоб тести/локальні підключення не ламались на CORS
		CheckOrigin: func(*http.Request) bool { return true },
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	// 1) Крипто-handshake ДО створення endpoint
	sessionKey, err := performServerHandshake(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}
	if len(sessionKey) != 32 {
		_ = conn.Close()
		return fmt.Errorf("sessionKey length invalid: %d", len(sessionKey))
	}

	// 2) Реєструємо сервіси
	registry := wsrpc.NewRegistry()
	if cfg.OnRegistry != nil {
		if err := cfg.OnRegistry(registry); err != nil {
			_ = conn.Close()
			return err
		}
	}

	// 3) Створюємо Endpoint
	endpoint, err := wetsock.NewEndpoint(registry, conn, string(sessionKey))
	if err != nil {
		_ = conn.Close()
		return err
	}

	// 4) СТАРТУЄМО Serve() ТУТ, щоб підключення стало активним негайно
	go func() {
		if err := endpoint.Serve(); err != nil && !websocket.IsCloseError(err,
			websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			log.Printf("[Server] Serve error: %v\n", err)
		}
	}()

	// 5) Додаткові дії користувача над endpoint (без Serve())
	if cfg.OnEndpoint != nil {
		if err := cfg.OnEndpoint(endpoint); err != nil {
			// Якщо хук повернув помилку — коректно закриваємо endpoint
			_ = endpoint.Close()
			return err
		}
	}

	// 6) НІЧОГО більше не робимо: з’єднання живе, Serve() уже крутиться у горутині
	return nil
}
