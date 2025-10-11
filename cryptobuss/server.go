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

	registryCache *wsrpc.Registry
	regOnce       sync.Once

	OnRegistry func(reg *wsrpc.Registry) error

	OnEndpoint func(*http.Request, string, *wsrpc.Endpoint) error

	conn   map[string]*wsrpc.Endpoint
	connMu sync.RWMutex

	Log func(format string, v ...any)
}

// Server виконує websocket-апгрейд, крипто-handshake, створює Endpoint і САМ запускає Serve().
// OnEndpoint викликається вже після створення endpoint (і після старту Serve()),
// тож у колбеку НЕ потрібно викликати Serve() вдруге.
func Server(cfg *ServerCfg, perm *wsrpc.Permission, w http.ResponseWriter, r *http.Request) error {
	if cfg == nil {
		return errors.New("server config is nil")
	}
	if cfg.Log == nil {
		cfg.Log = log.Printf
	}
	if len(cfg.SignPriv) == 0 || cfg.KeyID == "" {
		cfg.Log("[Server] ❌ Некоректна конфігурація: відсутній SignPriv або KeyID")
		return errors.New("server config incomplete: SignPriv and KeyID required")
	}

	if cfg.conn == nil {
		cfg.connMu.Lock()
		if cfg.conn == nil { // подвійна перевірка
			cfg.conn = map[string]*wsrpc.Endpoint{}
			cfg.Log("[Server] ініціалізовано мапу підключень")
		}
		cfg.connMu.Unlock()
	}

	upgrader := websocket.Upgrader{
		// Щоб тести/локальні підключення не ламались на CORS
		CheckOrigin: func(*http.Request) bool { return true },
	}

	cfg.Log("[Server] ⇢ Запит апгрейду від %s %s (KeyID=%s)\n", r.RemoteAddr, r.URL.Path, cfg.KeyID)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		cfg.Log("[Server] ❌ Помилка апгрейду WebSocket: %v\n", err)
		return err
	}
	cfg.Log("[Server] ✅ WebSocket апгрейд успішний")

	// 1) Крипто-handshake ДО створення endpoint
	cfg.Log("[Server] ⇢ Початок крипто-handshake (без логування секретів)")
	sessionKey, err := performServerHandshake(conn, cfg)
	if err != nil {
		cfg.Log("[Server] ❌ Handshake failed: %v\n", err)
		_ = conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}
	if len(sessionKey) != 32 {
		cfg.Log("[Server] ❌ Невірна довжина sessionKey: %d\n", len(sessionKey))
		_ = conn.Close()
		return fmt.Errorf("sessionKey length invalid: %d", len(sessionKey))
	}
	cfg.Log("[Server] ✅ Handshake успішний, ключ сесії отримано")

	// 2) Реєструємо сервіси (одноразово)

	cfg.regOnce.Do(func() {
		registry := wsrpc.NewRegistry()
		if cfg.OnRegistry != nil {
			cfg.Log("[Server] ⇢ Виклик OnRegistry()")
			if err := cfg.OnRegistry(registry); err != nil {
				cfg.Log("[Server] ❌ OnRegistry помилка: %v", err)
			} else {
				cfg.Log("[Server] ✅ OnRegistry завершився успішно")
			}
		} else {
			cfg.Log("[Server] ℹ️ OnRegistry не задано (продовжуємо з порожнім реєстром)")
		}
		cfg.Log("[Server] ✅ Endpoint methods: %s", registry.GetFunctionsName())
		cfg.registryCache = registry
	})
	if cfg.registryCache == nil {
		_ = conn.Close()
		return errors.New("registry initialization failed")
	}

	// 3) Створюємо Endpoint
	endpoint, err := wetsock.NewEndpoint(cfg.registryCache, perm, conn, string(sessionKey))
	if err != nil {
		cfg.Log("[Server] ❌ Помилка створення Endpoint: %v\n", err)
		_ = conn.Close()
		return err
	}
	id := uuid.NewString()
	cfg.Log("[Server] ✅ Endpoint створено: id=%s\n", id)

	// Зберігаємо підключення в індексі (раніше бракувало цього кроку)
	cfg.connMu.Lock()
	cfg.conn[id] = endpoint
	active := len(cfg.conn)
	cfg.connMu.Unlock()
	cfg.Log("[Server] 📇 Зареєстровано підключення: id=%s, активних=%d\n", id, active)

	var wg sync.WaitGroup

	// 4) СТАРТУЄМО Serve() ТУТ, щоб підключення стало активним негайно
	wg.Add(1)
	go func() {
		defer wg.Done() // ✅ раніше бракувало — тепер wg.Wait() не зависатиме
		defer func() {
			cfg.connMu.Lock()
			delete(cfg.conn, id)
			left := len(cfg.conn)
			cfg.connMu.Unlock()
			cfg.Log("[Server] 📴 Підключення закрито: id=%s, залишилось активних=%d\n", id, left)
		}()

		cfg.Log("[Server] ▶️ Serve стартував для id=%s\n", id)
		if err := endpoint.Serve(); err != nil && !websocket.IsCloseError(
			err, websocket.CloseNormalClosure, websocket.CloseGoingAway,
		) {
			cfg.Log("[Server] ⚠️ Serve error (id=%s): %v\n", id, err)
		}
		cfg.Log("[Server] ⏹ Serve завершено для id=%s\n", id)
	}()

	// 5) Додаткові дії користувача над endpoint (без Serve())
	if cfg.OnEndpoint != nil {
		cfg.Log("[Server] ⇢ Виклик OnEndpoint(id=%s)\n", id)
		if err := cfg.OnEndpoint(r, id, endpoint); err != nil {
			cfg.Log("[Server] ❌ OnEndpoint помилка (id=%s): %v\n", id, err)
			_ = endpoint.Close()
			return err
		}
		cfg.Log("[Server] ✅ OnEndpoint успішно (id=%s)\n", id)
	} else {
		cfg.Log("[Server] ℹ️ OnEndpoint не задано — пропускаємо")
	}

	wg.Wait()
	cfg.Log("[Server] ✅ Обробку запиту завершено (id=%s)\n", id)
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
	list := cfg.snapshot()
	cfg.Log("[Server] 🔁 ConnIter старт: всього=%d\n", len(list))

	var wg sync.WaitGroup
	for k, ep := range list {
		wg.Add(1)
		go func(id string, e *wsrpc.Endpoint) {
			defer wg.Done()
			if err := fn(id, e); err != nil {
				cfg.Log("[Server] ⚠️ ConnIter: функція повернула помилку для id=%s: %v — видаляю підключення\n", id, err)
				cfg.connMu.Lock()
				delete(cfg.conn, id)
				left := len(cfg.conn)
				cfg.connMu.Unlock()
				cfg.Log("[Server] 📉 Видалено проблемне підключення id=%s, активних=%d\n", id, left)
			}
		}(k, ep)
	}
	wg.Wait()
	cfg.Log("[Server] 🔁 ConnIter завершено")
}

func (cfg *ServerCfg) Broadcast(fn func(string, *wsrpc.Endpoint) error) {
	cfg.Log("[Server] 📣 Broadcast старт")
	cfg.ConnIter(fn)
	cfg.Log("[Server] 📣 Broadcast завершено ")
}

func (cfg *ServerCfg) ConnGet(key string) (bool, *wsrpc.Endpoint) {
	cfg.connMu.RLock()
	val, ok := cfg.conn[key]
	cfg.connMu.RUnlock()

	if ok {
		cfg.Log("[Server] 🔎 ConnGet: знайдено id=%s\n", key)
	} else {
		cfg.Log("[Server] 🔎 ConnGet: НЕ знайдено id=%s\n", key)
	}
	return ok, val
}

func (cfg *ServerCfg) ConnClose(key string) error {
	cfg.connMu.RLock()
	ep, ok := cfg.conn[key]
	cfg.connMu.RUnlock()
	if !ok {
		cfg.Log("[Server] 📴 ConnClose: id=%s вже відсутній\n", key)
		return nil
	}

	cfg.Log("[Server] 📴 Закриваю підключення id=%s\n", key)
	if err := ep.Close(); err != nil {
		cfg.Log("[Server] ❌ Помилка при закритті id=%s: %v\n", key, err)
		return err
	}
	cfg.connMu.Lock()
	delete(cfg.conn, key)
	left := len(cfg.conn)
	cfg.connMu.Unlock()
	cfg.Log("[Server] ✅ Закрито id=%s, активних=%d\n", key, left)
	return nil
}

func (cfg *ServerCfg) CloseAll() {
	list := cfg.snapshot()
	cfg.Log("[Server] 🧹 CloseAll: до закриття=%d\n", len(list))

	var wg sync.WaitGroup
	for k, ep := range list {
		wg.Add(1)
		go func(id string, e *wsrpc.Endpoint) {
			defer wg.Done()
			cfg.Log("[Server] 📴 Закриваю id=%s\n", id)
			_ = e.Close()
			cfg.connMu.Lock()
			delete(cfg.conn, id)
			left := len(cfg.conn)
			cfg.connMu.Unlock()
			cfg.Log("[Server] ✅ Закрито id=%s, активних=%d\n", id, left)
		}(k, ep)
	}
	wg.Wait()
	cfg.Log("[Server] 🧹 CloseAll завершено")
}
