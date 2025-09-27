package cryptobuss

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ServerCfg містить приватний підписний ключ сервера та ідентифікатор ключа (keyID).
// SignPriv має бути повним ed25519.PrivateKey (64 байти), KeyID — рядок для ротації.
type ServerCfg struct {
	SignPriv ed25519.PrivateKey
	KeyID    string
}

// --------------------------- Формати handshake ----------------------------

type handshakeRequest struct {
	Type               string `json:"type"`
	ClientEphemeralPub string `json:"client_ephemeral_pub"` // base64
	ClientNonce        string `json:"client_nonce"`         // base64
}

type handshakeResponse struct {
	Type               string `json:"type"`
	ServerEphemeralPub string `json:"server_ephemeral_pub"` // base64
	ServerNonce        string `json:"server_nonce"`         // base64
	ServerKeyID        string `json:"server_key_id"`
	Signature          string `json:"signature"` // base64 Ed25519 signature
}

// --------------------------- Утиліти X25519/HKDF ---------------------------

func genX25519KeyPair() (priv, pub [32]byte, err error) {
	_, err = io.ReadFull(crand.Reader, priv[:])
	if err != nil {
		return
	}
	// clamp приватний ключ
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func x25519DH(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	var out [32]byte
	curve25519.ScalarMult(&out, &priv, &peerPub)
	return out, nil
}

func deriveSessionKey(dh []byte, clientNonce, serverNonce []byte, serverKeyID string) ([]byte, error) {
	ikm := dh
	salt := append([]byte{}, clientNonce...)
	salt = append(salt, serverNonce...)
	info := []byte("wsrpc-session-v1|" + serverKeyID)
	hk := hkdf.New(sha256.New, ikm, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	return key, nil
}

// --------------------------- Серверний handshake --------------------------

// performServerHandshake виконує текстовий handshake і повертає 32-байтовий session key.
// cfg обов'язково має містити SignPriv (ed25519) і KeyID.
func performServerHandshake(conn *websocket.Conn, cfg *ServerCfg) ([]byte, error) {
	// Перевірка конфігурації
	if cfg == nil || cfg.SignPriv == nil || len(cfg.SignPriv) == 0 || cfg.KeyID == "" {
		return nil, errors.New("server config incomplete: SignPriv and KeyID required")
	}

	// Прочитати handshake request (текст)
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read handshake req: %w", err)
	}
	if mt != websocket.TextMessage {
		return nil, errors.New("expected text message for handshake")
	}
	var req handshakeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("unmarshal handshake req: %w", err)
	}

	// Декодуємо client ephemeral pub
	clientEphPubB, err := base64.StdEncoding.DecodeString(req.ClientEphemeralPub)
	if err != nil || len(clientEphPubB) != 32 {
		return nil, errors.New("invalid client_ephemeral_pub")
	}
	var clientEphPub [32]byte
	copy(clientEphPub[:], clientEphPubB)

	// Декодуємо client nonce
	clientNonce, err := base64.StdEncoding.DecodeString(req.ClientNonce)
	if err != nil {
		return nil, errors.New("invalid client_nonce")
	}
	if len(clientNonce) == 0 {
		return nil, errors.New("client_nonce empty")
	}

	// Генеруємо server ephemeral та nonce
	serverEphPriv, serverEphPub, err := genX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate server ephemeral: %w", err)
	}
	serverNonce := make([]byte, 12)
	if _, err := crand.Read(serverNonce); err != nil {
		return nil, fmt.Errorf("generate server nonce: %w", err)
	}

	// Обчислюємо DH: serverEphPriv x clientEphPub
	dh, err := x25519DH(serverEphPriv, clientEphPub)
	if err != nil {
		return nil, fmt.Errorf("compute dh: %w", err)
	}

	// Підпис payload: serverEphPub || clientEphPub || clientNonce || serverNonce || KeyID
	signPayload := make([]byte, 0, 32+32+len(clientNonce)+len(serverNonce)+len(cfg.KeyID))
	signPayload = append(signPayload, serverEphPub[:]...)
	signPayload = append(signPayload, clientEphPub[:]...)
	signPayload = append(signPayload, clientNonce...)
	signPayload = append(signPayload, serverNonce...)
	signPayload = append(signPayload, []byte(cfg.KeyID)...)

	signature := ed25519.Sign(cfg.SignPriv, signPayload)

	// Відправляємо response
	resp := handshakeResponse{
		Type:               "handshake_response",
		ServerEphemeralPub: base64.StdEncoding.EncodeToString(serverEphPub[:]),
		ServerNonce:        base64.StdEncoding.EncodeToString(serverNonce),
		ServerKeyID:        cfg.KeyID,
		Signature:          base64.StdEncoding.EncodeToString(signature),
	}
	respB, _ := json.Marshal(resp)
	conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, respB); err != nil {
		return nil, fmt.Errorf("write handshake resp: %w", err)
	}

	// Derive session key
	sessionKey, err := deriveSessionKey(dh[:], clientNonce, serverNonce, cfg.KeyID)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}

	// Опційно занулити приватні байти ephemeral
	_ = serverEphPriv // no-op placeholder for potential zeroing

	return sessionKey, nil
}

// --------------------------- Клієнтський handshake ------------------------

type ClientCfg struct {
	HttpHeaders    map[string]string
	Services       []interface{}
	RpcServerURL   string
	OnHttpResponse func(*http.Response) error
	stopped        chan struct{}
	// Пін (base64) публічного Ed25519 ключа сервера (видаєте клієнтам вручну)
	ServerSignPubBase64 string
}

func (cfg *ClientCfg) Stop() {
	// non-blocking stop so callers don't hang if channel already has a value
	if cfg == nil || cfg.stopped == nil {
		return
	}
	select {
	case cfg.stopped <- struct{}{}:
	default:
	}
}

func performClientHandshake(conn *websocket.Conn, serverSignPubBase64 string) ([]byte, error) {
	// server public key must be present
	if serverSignPubBase64 == "" {
		return nil, errors.New("serverSignPubBase64 required")
	}
	serverSignPubB, err := base64.StdEncoding.DecodeString(serverSignPubBase64)
	if err != nil || len(serverSignPubB) != ed25519.PublicKeySize {
		return nil, errors.New("invalid serverSignPubBase64")
	}
	serverSignPub := ed25519.PublicKey(serverSignPubB)

	// Генеруємо client ephemeral і nonce
	clientEphPriv, clientEphPub, err := genX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("gen client eph: %w", err)
	}
	clientNonce := make([]byte, 12)
	if _, err := crand.Read(clientNonce); err != nil {
		return nil, fmt.Errorf("gen client nonce: %w", err)
	}

	// Відправляємо handshake_request
	req := handshakeRequest{
		Type:               "handshake_request",
		ClientEphemeralPub: base64.StdEncoding.EncodeToString(clientEphPub[:]),
		ClientNonce:        base64.StdEncoding.EncodeToString(clientNonce),
	}
	reqB, _ := json.Marshal(req)
	conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, reqB); err != nil {
		return nil, fmt.Errorf("write handshake req: %w", err)
	}

	// Читаємо відповідь
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read handshake resp: %w", err)
	}
	if mt != websocket.TextMessage {
		return nil, errors.New("expected text handshake response")
	}
	var resp handshakeResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal handshake resp: %w", err)
	}

	// decode server ephemeral pub and nonce
	serverEphPubB, err := base64.StdEncoding.DecodeString(resp.ServerEphemeralPub)
	if err != nil || len(serverEphPubB) != 32 {
		return nil, errors.New("invalid server_ephemeral_pub")
	}
	var serverEphPub [32]byte
	copy(serverEphPub[:], serverEphPubB)

	serverNonce, err := base64.StdEncoding.DecodeString(resp.ServerNonce)
	if err != nil {
		return nil, errors.New("invalid server_nonce")
	}

	// verify signature
	sigB, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}
	signPayload := make([]byte, 0, 32+32+len(clientNonce)+len(serverNonce)+len(resp.ServerKeyID))
	signPayload = append(signPayload, serverEphPub[:]...)
	signPayload = append(signPayload, clientEphPub[:]...)
	signPayload = append(signPayload, clientNonce...)
	signPayload = append(signPayload, serverNonce...)
	signPayload = append(signPayload, []byte(resp.ServerKeyID)...)

	if !ed25519.Verify(serverSignPub, signPayload, sigB) {
		return nil, errors.New("server signature verification failed")
	}

	// compute DH: clientEphPriv x serverEphPub
	dh, err := x25519DH(clientEphPriv, serverEphPub)
	if err != nil {
		return nil, fmt.Errorf("compute dh: %w", err)
	}

	// derive session key
	sessionKey, err := deriveSessionKey(dh[:], clientNonce, serverNonce, resp.ServerKeyID)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}

	// Zero sensitive ephemeral priv optionally
	_ = clientEphPriv // placeholder for potential zeroing

	return sessionKey, nil
}

// --------------------------- Інтеграція в Server/Client --------------------

// Server тепер вимагає ServerCfg (тут передається підписний ключ і keyID).
// fn — реєстрація сервісів у registry; fnEnd — що робити з endpoint після створення.
func Server(cfg *ServerCfg, w http.ResponseWriter, r *http.Request, fn func(reg *wsrpc.Registry) error, fnEnd func(*wsrpc.Endpoint) error) error {
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
	if err := fn(registry); err != nil {
		conn.Close()
		return err
	}

	endpoint, err := wetsock.NewEndpoint(registry, conn, string(sessionKey))
	if err != nil {
		conn.Close()
		return err
	}

	return fnEnd(endpoint)
}

func Client(cfg *ClientCfg) error {
	// Обов'язковий pinned pub key
	if cfg == nil || cfg.ServerSignPubBase64 == "" {
		return errors.New("client config: ServerSignPubBase64 required")
	}

	// робимо stopped неблокуючим — Stop() не буде блокуватись
	cfg.stopped = make(chan struct{}, 1)

	// seed для джиттера backoff
	mrand.Seed(time.Now().UnixNano())

	// Создаем и регистрируем RPC сервис
	registry := wsrpc.NewRegistry()
	if len(cfg.Services) > 0 {
		for _, service := range cfg.Services {
			registry.RegisterService(service)
		}
	} else {
		log.Println("[WebSocket] Внимание: нет зарегистрированных сервисов!")
	}

	h := http.Header{}
	for key, val := range cfg.HttpHeaders {
		h.Set(key, val)
	}

	wsScheme := "ws"
	if strings.HasPrefix(cfg.RpcServerURL, "https://") {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/rpc", wsScheme, strings.TrimPrefix(strings.TrimPrefix(cfg.RpcServerURL, "http://"), "https://"))

	// параметры переподключения
	baseDelay := 500 * time.Millisecond
	maxDelay := 30 * time.Second
	attempt := 0

	for {
		// если нам приказали остановиться — выходим
		select {
		case <-cfg.stopped:
			log.Println("[WebSocket] Остановка WebSocket-переподключений")
			return nil
		default:
		}

		log.Println("[WebSocket] Попытка подключения к серверу...")

		conn, res, err := websocket.DefaultDialer.Dial(wsURL, h)
		if err != nil {
			// Dial failed — retry with backoff + jitter
			log.Println("[WebSocket] Dial error:", err)
			// compute backoff (exponential)
			sleep := baseDelay * (1 << attempt)
			if sleep > maxDelay {
				sleep = maxDelay
			}
			// jitter: [0, sleep/2)
			j := time.Duration(mrand.Int63n(int64(sleep / 2)))
			sleep = sleep + j
			attempt++
			// wait or exit if stopped
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}

		// успешный dial — сбрасываем попытки
		attempt = 0

		if cfg.OnHttpResponse != nil {
			if err = cfg.OnHttpResponse(res); err != nil {
				// OnHttpResponse может вернуть ошибку — закрываем и пробуем снова
				log.Println("[WebSocket] OnHttpResponse error:", err)
				conn.Close()
				// небольшой backoff перед новой попыткой
				sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
				select {
				case <-cfg.stopped:
					return nil
				case <-time.After(sleep):
					continue
				}
			}
		}

		// Выполняем handshake (перед созданием wetsock.Endpoint)
		sessionKey, err := performClientHandshake(conn, cfg.ServerSignPubBase64)
		if err != nil {
			log.Println("[KeyExchange] handshake failed:", err)
			conn.Close()
			// backoff перед повторной попыткой
			sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}
		if len(sessionKey) != 32 {
			log.Println("[KeyExchange] invalid session key length:", len(sessionKey))
			conn.Close()
			sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}

		// Создаем RPC-эндпоинт с полученным sessionKey
		endpoint, err := wetsock.NewEndpoint(registry, conn, string(sessionKey))
		if err != nil {
			// не создался endpoint — закрываем и пробуем снова
			log.Println("[WebSocket NewEndpoint] Внимание:", err)
			conn.Close()
			sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}

		// Успешно подключились и создали endpoint — начинаем Serve()
		if err := endpoint.Serve(); err != nil {
			log.Println("[WebSocket] Соединение закрыто:", err)
		}

		// Когда Serve() завершился — либо соединение закрылось, либо произошла ошибка.
		// Делаем короткую паузу и переподключаемся (если не остановлены).
		select {
		case <-cfg.stopped:
			// попытка аккуратно закрыть endpoint (если еще не закрыт)
			_ = endpoint.Close()
			return nil
		default:
		}
		// небольшой backoff между сессиями (чтобы не спамить при мгновенных провалах)
		sleep := 1*time.Second + time.Duration(mrand.Int63n(int64(1000*time.Millisecond)))
		select {
		case <-cfg.stopped:
			_ = endpoint.Close()
			return nil
		case <-time.After(sleep):
			// loop продолжится и попробуем переподключиться
		}
	}
}
