package cryptobuss

import (
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

type ClientCfg struct {
	HttpHeaders    map[string]string
	Services       []interface{}
	RpcServerURL   string
	OnHttpResponse func(*http.Response) error
	stopped        chan struct{}

	// Пін (base64) Ed25519 публічного ключа сервера
	ServerSignPubBase64 string

	// ---- НОВЕ: керування перепідключеннями ----
	// Скільки разів поспіль можна намагатись підключитись після розриву (0 = безліміт)
	MaxReconnects int

	// Загальний бюджет часу на перепідключення після одного розриву (0 = безліміт)
	// Вимірюється з моменту першої невдалої спроби.
	TotalRetryTimeout time.Duration

	// Базова й максимальна затримки backoff (якщо 0 — використовуються дефолти 500ms/30s)
	BaseDelay time.Duration
	MaxDelay  time.Duration

	// Частка джиттера [0..1], напр. 0.5 означає ±50% випадковості (якщо 0 — дефолт 0.5)
	JitterFrac float64

	// Колбеки (необов'язкові)
	OnReconnectAttempt func(attempt int, sleep time.Duration, lastErr error) bool
	OnConnected        func(endpoint *wsrpc.Endpoint)                  // коли з’єднання встановлено
	OnDisconnected     func(err error)                                 // коли Serve() завершився
	OnGiveUp           func(reason string, attempt int, lastErr error) // коли припиняємо спроби
}

// обмеження shift’ів, дефолти, джиттер і «стеля»
func (cfg *ClientCfg) nextBackoff(attempt int) time.Duration {
	base := cfg.BaseDelay
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	maxd := cfg.MaxDelay
	if maxd <= 0 {
		maxd = 30 * time.Second
	}
	// експоненційно, але з безпечною «стелею»
	// 1<<attempt може переповнитись — обмежимося поки sleep < maxd
	sleep := base
	for i := 0; i < attempt; i++ {
		sleep *= 2
		if sleep >= maxd {
			sleep = maxd
			break
		}
	}
	jf := cfg.JitterFrac
	if jf <= 0 || jf > 1 {
		jf = 0.5
	}
	// джиттер у межах ±jf
	// напр., jf=0.5 → діапазон [0.5..1.5]*sleep
	delta := time.Duration(float64(sleep) * jf)
	low := sleep - delta
	high := sleep + delta
	if high <= low {
		return sleep
	}
	// rand у вже засіяному mrand
	jitter := time.Duration(mrand.Int63n(int64(high-low))) + low
	if jitter > maxd {
		jitter = maxd
	}
	if jitter < 0 {
		jitter = 0
	}
	return jitter
}

func Client(keyID string, cfg *ClientCfg) error {
	if cfg == nil || cfg.ServerSignPubBase64 == "" {
		log.Println("[Client] ❌ Некоректна конфігурація: ServerSignPubBase64 порожній")
		return errors.New("client config: ServerSignPubBase64 required")
	}
	cfg.stopped = make(chan struct{}, 1)
	mrand.Seed(time.Now().UnixNano())

	registry := wsrpc.NewRegistry()
	for i, s := range cfg.Services {
		registry.RegisterService(s)
		log.Printf("[Client] 🔌 Зареєстровано сервіс #%d\n", i+1)
	}

	// Підготовка заголовків (логую лише ключі, без значень)
	h := http.Header{}
	if n := len(cfg.HttpHeaders); n > 0 {
		for k, v := range cfg.HttpHeaders {
			h.Set(k, v)
		}
		log.Printf("[Client] 📨 Заголовки до запиту: %v\n", headerKeysOnly(cfg.HttpHeaders))
	}

	wsScheme := "ws"
	if strings.HasPrefix(cfg.RpcServerURL, "https://") {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/rpc-cryptobuss", wsScheme, strings.TrimPrefix(strings.TrimPrefix(cfg.RpcServerURL, "http://"), "https://"))
	log.Printf("[Client] 🌐 WebSocket URL: %s (scheme=%s)\n", wsURL, wsScheme)

	attempt := 0
	var deadline time.Time
	var lastErr error
	var sessions uint64 // лічильник сесій підключень

	// локальний хелпер очікування зі всіма перевірками
	waitOrStop := func(sleep time.Duration, reason string) bool {
		if !deadline.IsZero() && time.Now().Add(sleep).After(deadline) {
			if cfg.OnGiveUp != nil {
				cfg.OnGiveUp("total-timeout", attempt, lastErr)
			}
			log.Printf("[Client] ⏱️ Перевищено загальний бюджет часу перепідключень (%s). Завершую.\n", reason)
			return false
		}
		select {
		case <-cfg.stopped:
			if cfg.OnGiveUp != nil {
				cfg.OnGiveUp("stopped", attempt, lastErr)
			}
			log.Println("[Client] ⏹ Отримано Stop() — вихід")
			return false
		case <-time.After(sleep):
			return true
		}
	}

	for {
		// «м’який» вихід
		select {
		case <-cfg.stopped:
			log.Println("[Client] ⏹ Зупинка запитана до підключення — вихід")
			return nil
		default:
		}

		log.Printf("[Client] ▶️ Спроба підключення #%d до %s ...\n", attempt+1, wsURL)

		conn, res, err := websocket.DefaultDialer.Dial(wsURL, h)
		if err != nil {
			lastErr = err
			log.Printf("[Client] ❌ Dial error (attempt=%d): %v\n", attempt+1, err)

			// стартуємо вікно TotalRetryTimeout з першого фейлу
			if attempt == 0 && cfg.TotalRetryTimeout > 0 && deadline.IsZero() {
				deadline = time.Now().Add(cfg.TotalRetryTimeout)
				log.Printf("[Client] ⏱️ Старт вікна TotalRetryTimeout: %s\n", cfg.TotalRetryTimeout)
			}

			// ліміт спроб?
			if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
				if cfg.OnGiveUp != nil {
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
				}
				return fmt.Errorf("dial failed: %w (max reconnects reached)", err)
			}

			sleep := cfg.nextBackoff(attempt)
			log.Printf("[Client] 💤 Backoff перед наступною спробою: %s (attempt=%d)\n", sleep, attempt+1)

			if cfg.OnReconnectAttempt != nil {
				if !cfg.OnReconnectAttempt(attempt+1, sleep, lastErr) {
					log.Println("[Client] 🛑 OnReconnectAttempt повернув false — припиняю")
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
					return nil
				}
			}
			attempt++
			if !waitOrStop(sleep, "dial-backoff") {
				return nil
			}
			continue
		}

		// dial ok → скидаємо лічильники
		attempt = 0
		deadline = time.Time{}
		sessions++
		log.Printf("[Client] ✅ Dial успішний (session=%d)\n", sessions)

		// Колбек з HTTP-відповіддю (рукостискання)
		if cfg.OnHttpResponse != nil {
			log.Printf("[Client] ⇢ OnHttpResponse: status=%s, code=%d\n", res.Status, res.StatusCode)
			if err = cfg.OnHttpResponse(res); err != nil {
				lastErr = err
				log.Printf("[Client] ❌ OnHttpResponse помилка: %v\n", err)
				_ = conn.Close()

				if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
					if cfg.OnGiveUp != nil {
						cfg.OnGiveUp("max-reconnects", attempt, lastErr)
					}
					return fmt.Errorf("OnHttpResponse: %w", err)
				}
				sleep := cfg.nextBackoff(attempt)
				log.Printf("[Client] 💤 Backoff після OnHttpResponse: %s (attempt=%d)\n", sleep, attempt+1)

				if cfg.OnReconnectAttempt != nil {
					if !cfg.OnReconnectAttempt(attempt+1, sleep, lastErr) {
						log.Println("[Client] 🛑 OnReconnectAttempt=false після OnHttpResponse — припиняю")
						cfg.OnGiveUp("max-reconnects", attempt, lastErr)
						return nil
					}
				}
				attempt++
				if !waitOrStop(sleep, "http-response") {
					return nil
				}
				continue
			}
		}

		log.Printf("[Client] ⇢ Початок крипто-handshake (session=%d)\n", sessions)
		sessionKey, err := performClientHandshake(conn, cfg.ServerSignPubBase64, keyID)
		if err != nil || len(sessionKey) != 32 {
			if err == nil {
				err = fmt.Errorf("invalid session key length: %d", len(sessionKey))
			}
			lastErr = err
			log.Printf("[Client] ❌ Handshake failed: %v\n", err)
			_ = conn.Close()

			if attempt == 0 && cfg.TotalRetryTimeout > 0 && deadline.IsZero() {
				deadline = time.Now().Add(cfg.TotalRetryTimeout)
				log.Printf("[Client] ⏱️ Старт TotalRetryTimeout: %s\n", cfg.TotalRetryTimeout)
			}
			if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
				if cfg.OnGiveUp != nil {
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
				}
				return fmt.Errorf("handshake failed: %w", err)
			}
			sleep := cfg.nextBackoff(attempt)
			log.Printf("[Client] 💤 Backoff після помилки handshake: %s (attempt=%d)\n", sleep, attempt+1)

			if cfg.OnReconnectAttempt != nil {
				if !cfg.OnReconnectAttempt(attempt+1, sleep, lastErr) {
					log.Println("[Client] 🛑 OnReconnectAttempt=false після handshake — припиняю")
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
					return nil
				}
			}
			attempt++
			if !waitOrStop(sleep, "handshake") {
				return nil
			}
			continue
		}
		log.Printf("[Client] ✅ Handshake успішний (session=%d)\n", sessions)

		endpoint, err := wetsock.NewEndpoint(registry, nil, conn, string(sessionKey))
		if err != nil {
			lastErr = err
			log.Printf("[Client] ❌ NewEndpoint error: %v\n", err)
			_ = conn.Close()

			if attempt == 0 && cfg.TotalRetryTimeout > 0 && deadline.IsZero() {
				deadline = time.Now().Add(cfg.TotalRetryTimeout)
				log.Printf("[Client] ⏱️ Старт TotalRetryTimeout: %s\n", cfg.TotalRetryTimeout)
			}
			if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
				if cfg.OnGiveUp != nil {
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
				}
				return fmt.Errorf("NewEndpoint: %w", err)
			}
			sleep := cfg.nextBackoff(attempt)
			log.Printf("[Client] 💤 Backoff після NewEndpoint: %s (attempt=%d)\n", sleep, attempt+1)

			if cfg.OnReconnectAttempt != nil {
				if !cfg.OnReconnectAttempt(attempt+1, sleep, lastErr) {
					log.Println("[Client] 🛑 OnReconnectAttempt=false після NewEndpoint — припиняю")
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
					return nil
				}
			}
			attempt++
			if !waitOrStop(sleep, "new-endpoint") {
				return nil
			}
			continue
		}

		log.Printf("[Client] 🔗 Підключено (session=%d). Запускаю Serve() ...\n", sessions)
		if cfg.OnConnected != nil {
			cfg.OnConnected(endpoint)
		}

		// Блокуємось у Serve() до розриву
		if err := endpoint.Serve(); err != nil {
			lastErr = err
			log.Printf("[Client] ⚠️ Serve завершився з помилкою: %v (session=%d)\n", err, sessions)
			if cfg.OnDisconnected != nil {
				cfg.OnDisconnected(err)
			}
		} else {
			log.Printf("[Client] ⏹ Serve завершено без помилок (session=%d)\n", sessions)
			if cfg.OnDisconnected != nil {
				cfg.OnDisconnected(nil)
			}
		}

		// після розриву — пауза між сесіями (м’який «cooldown», не backoff)
		cooldown := 1*time.Second + time.Duration(mrand.Int63n(int64(1000*time.Millisecond)))
		log.Printf("[Client] 🧊 Cooldown між сесіями: %s\n", cooldown)
		select {
		case <-cfg.stopped:
			log.Println("[Client] ⏹ Stop() під час cooldown — закриваю endpoint і виходжу")
			_ = endpoint.Close()
			return nil
		case <-time.After(cooldown):
		}

		// при переході до нового циклу перепідключень стартуємо бюджет часу
		attempt = 0
		deadline = time.Time{}
		log.Println("[Client] 🔁 Перехід до нового циклу перепідключень")
	}
}

func (cfg *ClientCfg) Stop() {
	if cfg == nil || cfg.stopped == nil {
		return
	}
	select {
	case cfg.stopped <- struct{}{}:
		log.Println("[Client] ⏹ Stop() надіслано")
	default:
		log.Println("[Client] ⏹ Stop() вже був надісланий раніше")
	}
}

// Допоміжне: повертає лише перелік ключів заголовків для безпечного логування
func headerKeysOnly(h map[string]string) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
