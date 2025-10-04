package cryptobuss

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

// ServerCfg містить приватний підписний ключ сервера та ідентифікатор ключа (keyID).
type ServerCfg struct {
	SignPriv ed25519.PrivateKey
	KeyID    string

	OnRegistry func(reg *wsrpc.Registry) error

	OnEndpoint func(*http.Request, string, *wsrpc.Endpoint) error

	conn   map[string]*wsrpc.Endpoint
	connMu sync.RWMutex
}

// Server виконує websocket-апгрейд, крипто-handshake, створює Endpoint і САМ запускає Serve().
// OnEndpoint викликається вже після створення endpoint (і після старту Serve()),
// тож у колбеку НЕ потрібно викликати Serve() вдруге.
func Server(cfg *ServerCfg, w http.ResponseWriter, r *http.Request) error {
	if cfg == nil || cfg.SignPriv == nil || len(cfg.SignPriv) == 0 || cfg.KeyID == "" {
		return errors.New("server config incomplete: SignPriv and KeyID required")
	}

	if cfg.conn == nil {
		cfg.connMu.Lock()
		cfg.conn = map[string]*wsrpc.Endpoint{}
		cfg.connMu.Unlock()
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
	id := uuid.NewString()

	wg := sync.WaitGroup{}
	// 4) СТАРТУЄМО Serve() ТУТ, щоб підключення стало активним негайно
	wg.Add(1)
	go func() {
		defer func() {
			cfg.connMu.Lock()
			delete(cfg.conn, id)
			cfg.connMu.Unlock()
		}()
		if err := endpoint.Serve(); err != nil && !websocket.IsCloseError(err,
			websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			log.Printf("[Server] Serve error: %v\n", err)
		}
	}()

	// 5) Додаткові дії користувача над endpoint (без Serve())
	if cfg.OnEndpoint != nil {
		if err := cfg.OnEndpoint(r, id, endpoint); err != nil {
			// Якщо хук повернув помилку — коректно закриваємо endpoint
			_ = endpoint.Close()
			return err
		}
	}

	wg.Wait()
	return nil
}

func (cfg *ServerCfg) snapshot() map[string]*wsrpc.Endpoint {
	cfg.connMu.RLock()
	defer cfg.connMu.RUnlock()
	cp := make(map[string]*wsrpc.Endpoint, len(cfg.conn))
	for k, v := range cfg.conn {
		cp[k] = v
	}
	return cp
}

func (cfg *ServerCfg) ConnIter(fn func(string, *wsrpc.Endpoint) error) {
	var wg sync.WaitGroup
	for k, ep := range cfg.snapshot() {
		wg.Add(1)
		go func(id string, e *wsrpc.Endpoint) {
			defer wg.Done()
			if err := fn(id, e); err != nil {
				// видалити проблемне підключення
				cfg.connMu.Lock()
				delete(cfg.conn, id)
				cfg.connMu.Unlock()
			}
		}(k, ep)
	}
	wg.Wait()
}

func (cfg *ServerCfg) Broadcast(fn func(string, *wsrpc.Endpoint) error) {
	cfg.ConnIter(fn)
}

func (cfg *ServerCfg) ConnGet(key string) (bool, *wsrpc.Endpoint) {
	cfg.connMu.RLock()
	val, ok := cfg.conn[key]
	cfg.connMu.RUnlock()

	return ok, val
}

func (cfg *ServerCfg) ConnClose(key string) error {
	cfg.connMu.RLock()
	ep, ok := cfg.conn[key]
	cfg.connMu.RUnlock()
	if !ok {
		return nil
	}
	// Спочатку закрити
	if err := ep.Close(); err != nil {
		return err
	}
	// Потім стерти (Serve() теж видалить у своєму defer — подвійне delete безпечний)
	cfg.connMu.Lock()
	delete(cfg.conn, key)
	cfg.connMu.Unlock()
	return nil
}

func (cfg *ServerCfg) CloseAll() {
	var wg sync.WaitGroup
	for k, ep := range cfg.snapshot() {
		wg.Add(1)
		go func(id string, e *wsrpc.Endpoint) {
			defer wg.Done()
			_ = e.Close()
			cfg.connMu.Lock()
			delete(cfg.conn, id)
			cfg.connMu.Unlock()
		}(k, ep)
	}
	wg.Wait()
}
