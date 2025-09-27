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
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

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
