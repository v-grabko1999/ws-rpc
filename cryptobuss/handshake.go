package cryptobuss

import (
    "crypto/ed25519"
    crand "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "time"

    "github.com/gorilla/websocket"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/hkdf"
)

// handshakeRequest is sent from client to server to initiate a handshake.
// It includes a type field, client ephermal public key, client nonce and a
// timestamp. The timestamp helps to protect against replay attacks. The
// nonce and timestamp are both included in the signature computation.
type handshakeRequest struct {
    Type               string `json:"type"`
    ClientEphemeralPub string `json:"client_ephemeral_pub"`
    ClientNonce        string `json:"client_nonce"`
    Timestamp          int64  `json:"timestamp"`
}

// handshakeResponse is sent from server to client after validating the
// request. It includes a type field, server ephermal public key, server
// nonce, server key ID, a signature and a timestamp. The signature covers
// the ephermal keys, nonces, key ID and timestamps.
type handshakeResponse struct {
    Type               string `json:"type"`
    ServerEphemeralPub string `json:"server_ephemeral_pub"`
    ServerNonce        string `json:"server_nonce"`
    ServerKeyID        string `json:"server_key_id"`
    Signature          string `json:"signature"`
    Timestamp          int64  `json:"timestamp"`
}

// genX25519KeyPair generates an X25519 key pair. The private key is clamped
// according to RFC 7748.
func genX25519KeyPair() (priv, pub [32]byte, err error) {
    _, err = io.ReadFull(crand.Reader, priv[:])
    if err != nil {
        return
    }
    // Clamp the private key.
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    curve25519.ScalarBaseMult(&pub, &priv)
    return
}

// x25519DH computes a Diffie–Hellman shared secret using the given X25519
// private key and peer public key.
func x25519DH(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
    var out [32]byte
    curve25519.ScalarMult(&out, &priv, &peerPub)
    return out, nil
}

// deriveSessionKey derives a 32-byte session key from the DH secret, nonces
// and server key ID using HKDF-SHA256.
func deriveSessionKey(dh []byte, clientNonce, serverNonce []byte, serverKeyID string, clientTS, serverTS int64) ([]byte, error) {
    // combine nonces and timestamps for salt and info
    salt := append([]byte{}, clientNonce...)
    salt = append(salt, serverNonce...)
    // include both timestamps in the info to ensure uniqueness
    info := []byte(fmt.Sprintf("wsrpc-session-v2|%s|%d|%d", serverKeyID, clientTS, serverTS))
    hk := hkdf.New(sha256.New, dh, salt, info)
    key := make([]byte, 32)
    if _, err := io.ReadFull(hk, key); err != nil {
        return nil, err
    }
    return key, nil
}

// performServerHandshake performs the server side of the handshake. It
// validates the incoming request, responds with its own ephermal public key
// and nonce, signs the payload and derives a session key. The session key
// is returned if all validations succeed.
func performServerHandshake(conn *websocket.Conn, cfg *ServerCfg) ([]byte, error) {
    // Validate config.
    if cfg == nil || cfg.SignPriv == nil || len(cfg.SignPriv) == 0 || cfg.KeyID == "" {
        return nil, errors.New("server config incomplete: SignPriv and KeyID required")
    }
    // Reject overly long KeyID to prevent resource exhaustion.
    if len(cfg.KeyID) > 128 {
        return nil, fmt.Errorf("server KeyID too long: %d bytes", len(cfg.KeyID))
    }

    // Read the handshake request. Use a read deadline to avoid hanging.
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

    // Validate request type.
    if req.Type != "handshake_request" {
        return nil, fmt.Errorf("unexpected handshake type: %s", req.Type)
    }
    // Validate timestamp: must be within 30 seconds of current time.
    if req.Timestamp == 0 {
        return nil, errors.New("handshake request missing timestamp")
    }
    reqTime := time.Unix(req.Timestamp, 0)
    if d := time.Since(reqTime); d < -30*time.Second || d > 30*time.Second {
        return nil, fmt.Errorf("handshake request timestamp out of range: %v", d)
    }

    // Decode client ephermal public key.
    clientEphPubB, err := base64.StdEncoding.DecodeString(req.ClientEphemeralPub)
    if err != nil || len(clientEphPubB) != 32 {
        return nil, errors.New("invalid client_ephemeral_pub")
    }
    var clientEphPub [32]byte
    copy(clientEphPub[:], clientEphPubB)

    // Decode client nonce.
    clientNonce, err := base64.StdEncoding.DecodeString(req.ClientNonce)
    if err != nil {
        return nil, errors.New("invalid client_nonce")
    }
    if len(clientNonce) == 0 {
        return nil, errors.New("client_nonce empty")
    }

    // Generate server ephermal key pair and nonce.
    serverEphPriv, serverEphPub, err := genX25519KeyPair()
    if err != nil {
        return nil, fmt.Errorf("generate server ephermal: %w", err)
    }
    serverNonce := make([]byte, 12)
    if _, err := crand.Read(serverNonce); err != nil {
        return nil, fmt.Errorf("generate server nonce: %w", err)
    }
    serverTS := time.Now().Unix()

    // Compute shared secret.
    dh, err := x25519DH(serverEphPriv, clientEphPub)
    if err != nil {
        return nil, fmt.Errorf("compute dh: %w", err)
    }

    // Compute signature payload: serverEphPub || clientEphPub || clientNonce || serverNonce || KeyID || req.Timestamp || serverTimestamp.
    signPayload := make([]byte, 0, 32+32+len(clientNonce)+len(serverNonce)+len(cfg.KeyID)+16)
    signPayload = append(signPayload, serverEphPub[:]...)
    signPayload = append(signPayload, clientEphPub[:]...)
    signPayload = append(signPayload, clientNonce...)
    signPayload = append(signPayload, serverNonce...)
    signPayload = append(signPayload, []byte(cfg.KeyID)...)
    // Encode timestamps as 8-byte big endian.
    tsBuf := make([]byte, 8)
    binary.BigEndian.PutUint64(tsBuf, uint64(req.Timestamp))
    signPayload = append(signPayload, tsBuf...)
    binary.BigEndian.PutUint64(tsBuf, uint64(serverTS))
    signPayload = append(signPayload, tsBuf...)

    signature := ed25519.Sign(cfg.SignPriv, signPayload)

    // Send handshake response.
    resp := handshakeResponse{
        Type:               "handshake_response",
        ServerEphemeralPub: base64.StdEncoding.EncodeToString(serverEphPub[:]),
        ServerNonce:        base64.StdEncoding.EncodeToString(serverNonce),
        ServerKeyID:        cfg.KeyID,
        Signature:          base64.StdEncoding.EncodeToString(signature),
        Timestamp:          serverTS,
    }
    respB, _ := json.Marshal(resp)
    conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
    if err := conn.WriteMessage(websocket.TextMessage, respB); err != nil {
        return nil, fmt.Errorf("write handshake resp: %w", err)
    }

    // Derive session key from DH secret and nonces, and timestamps.
    sessionKey, err := deriveSessionKey(dh[:], clientNonce, serverNonce, cfg.KeyID, req.Timestamp, serverTS)
    if err != nil {
        return nil, fmt.Errorf("derive session key: %w", err)
    }

    // Zero ephermal private key (left as no-op placeholder).
    _ = serverEphPriv

    return sessionKey, nil
}

// performClientHandshake performs the client side of the handshake. It
// generates a new ephermal key pair and nonce, sends a request with a
// timestamp, reads the response, verifies the server's signature and
// timestamp, and derives a session key.
func performClientHandshake(conn *websocket.Conn, serverSignPubBase64 string, expectedServerKeyID string) ([]byte, error) {
    if serverSignPubBase64 == "" {
        return nil, errors.New("serverSignPubBase64 required")
    }
    serverSignPubB, err := base64.StdEncoding.DecodeString(serverSignPubBase64)
    if err != nil || len(serverSignPubB) != ed25519.PublicKeySize {
        return nil, errors.New("invalid serverSignPubBase64")
    }
    serverSignPub := ed25519.PublicKey(serverSignPubB)

    // Generate client ephermal key pair and nonce.
    clientEphPriv, clientEphPub, err := genX25519KeyPair()
    if err != nil {
        return nil, fmt.Errorf("gen client eph: %w", err)
    }
    clientNonce := make([]byte, 12)
    if _, err := crand.Read(clientNonce); err != nil {
        return nil, fmt.Errorf("gen client nonce: %w", err)
    }
    clientTS := time.Now().Unix()

    // Send handshake request with timestamp.
    req := handshakeRequest{
        Type:               "handshake_request",
        ClientEphemeralPub: base64.StdEncoding.EncodeToString(clientEphPub[:]),
        ClientNonce:        base64.StdEncoding.EncodeToString(clientNonce),
        Timestamp:          clientTS,
    }
    reqB, _ := json.Marshal(req)
    conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
    if err := conn.WriteMessage(websocket.TextMessage, reqB); err != nil {
        return nil, fmt.Errorf("write handshake req: %w", err)
    }

    // Read handshake response.
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

    // Validate response type.
    if resp.Type != "handshake_response" {
        return nil, fmt.Errorf("unexpected handshake type: %s", resp.Type)
    }
    // Validate server KeyID if expectedServerKeyID is provided.
    if expectedServerKeyID != "" && resp.ServerKeyID != expectedServerKeyID {
        return nil, fmt.Errorf("unexpected server_key_id: got %s, want %s", resp.ServerKeyID, expectedServerKeyID)
    }
    // Validate response timestamp.
    if resp.Timestamp == 0 {
        return nil, errors.New("handshake response missing timestamp")
    }
    respTime := time.Unix(resp.Timestamp, 0)
    if d := time.Since(respTime); d < -30*time.Second || d > 30*time.Second {
        return nil, fmt.Errorf("handshake response timestamp out of range: %v", d)
    }

    // Decode server ephermal public key and nonce.
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

    // Verify signature: serverEphPub || clientEphPub || clientNonce || serverNonce || KeyID || clientTS || serverTS.
    sigB, err := base64.StdEncoding.DecodeString(resp.Signature)
    if err != nil {
        return nil, errors.New("invalid signature encoding")
    }
    signPayload := make([]byte, 0, 32+32+len(clientNonce)+len(serverNonce)+len(resp.ServerKeyID)+16)
    signPayload = append(signPayload, serverEphPub[:]...)
    signPayload = append(signPayload, clientEphPub[:]...)
    signPayload = append(signPayload, clientNonce...)
    signPayload = append(signPayload, serverNonce...)
    signPayload = append(signPayload, []byte(resp.ServerKeyID)...)
    tsBuf := make([]byte, 8)
    binary.BigEndian.PutUint64(tsBuf, uint64(clientTS))
    signPayload = append(signPayload, tsBuf...)
    binary.BigEndian.PutUint64(tsBuf, uint64(resp.Timestamp))
    signPayload = append(signPayload, tsBuf...)

    if !ed25519.Verify(serverSignPub, signPayload, sigB) {
        return nil, errors.New("server signature verification failed")
    }

    // Compute shared secret.
    dh, err := x25519DH(clientEphPriv, serverEphPub)
    if err != nil {
        return nil, fmt.Errorf("compute dh: %w", err)
    }

    // Derive session key using timestamps.
    sessionKey, err := deriveSessionKey(dh[:], clientNonce, serverNonce, resp.ServerKeyID, clientTS, resp.Timestamp)
    if err != nil {
        return nil, fmt.Errorf("derive session key: %w", err)
    }

    // Zero ephermal private key (left as no-op placeholder).
    _ = clientEphPriv

    return sessionKey, nil
}