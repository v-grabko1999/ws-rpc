package wsrpc_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/websocket"

	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

const testKey = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" // 32 'q'

// ServerService — сервис, который вызывает метод на клиенте
type ServerService struct{}

func (s *ServerService) CallClient(_ *struct{}, _ *struct{}, ep *wsrpc.Endpoint) error {
	log.Println("[Server] Клиент вызвал сервер, вызываем ClientFunc на клиенте")
	var reply struct{}
	return ep.Call("ClientService.ClientFunc", &struct{}{}, &reply)
}

// ClientService — сервис, который вызывается сервером
type ClientService struct {
	Done chan struct{}
}

func (c *ClientService) ClientFunc(_ *struct{}, _ *struct{}) error {
	log.Println("[Client] Сервер вызвал ClientFunc, сигнализируем Done")
	close(c.Done)
	return nil
}

func isCloseErr(err error) bool {
	if err == io.EOF {
		return true
	}
	return websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway)
}

func TestBidirectionalRPC(t *testing.T) {
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Канал, через который HandlerFunc отдасть нам свой endpoint
	serverEPCh := make(chan *wsrpc.Endpoint, 1)

	// Поднимаем тестовый HTTP+WebSocket сервер
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade failed: %v", err)
		}

		// Создаем серверный endpoint и шлём его в main-гору
		registry := wsrpc.NewRegistry()
		registry.RegisterService(&ServerService{})
		ep, err := wetsock.NewEndpoint(registry, conn, testKey)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		serverEPCh <- ep

		// Запускаем Serve() для сервера
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Println("[Server] Начинаем Serve()")
			if err := ep.Serve(); err != nil && !isCloseErr(err) {
				t.Errorf("server Serve error: %v", err)
			}
			log.Println("[Server] Serve() завершился")
		}()
	}))
	defer s.Close()

	// Подключаем клиента
	wsURL := "ws" + s.URL[4:]

	// Настраиваем клиентский endpoint
	clientRegistry := wsrpc.NewRegistry()
	clientSvc := &ClientService{Done: done}
	clientRegistry.RegisterService(clientSvc)
	clientEP, err := wetsock.NewAutoEndpoint(clientRegistry, wsURL, http.Header{}, testKey)
	if err != nil {
		t.Fatalf("NewEndpoint (client) failed: %v", err)
	}

	// Запускаем Serve() для клиента
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("[Client] Начинаем Serve()")
		if err := clientEP.Serve(); err != nil && !isCloseErr(err) {
			t.Errorf("client Serve error: %v", err)
		}
		log.Println("[Client] Serve() завершился")
	}()

	// Получаем серверный endpoint из handler’а
	serverEP := <-serverEPCh

	// Делаем первый вызов: клиент → сервер → клиент
	var reply struct{}
	if err := clientEP.Call("ServerService.CallClient", &struct{}{}, &reply); err != nil {
		t.Fatalf("client.Call error: %v", err)
	}

	// Ждём, пока ClientService.ClientFunc закроет done
	<-done

	// Теперь мы завершаем оба endpoint’а в явном порядке
	if err := clientEP.Close(); err != nil {
		t.Errorf("client Close error: %v", err)
	}
	if err := serverEP.Close(); err != nil {
		t.Errorf("server Close error: %v", err)
	}

	// Ждём, пока оба Serve() закончатся
	wg.Wait()

}

/*
// Генерує пару X25519 (приватний 32 байти, публічний 32 байти)
func genX25519KeyPair() (priv, pub [32]byte, err error) {
	_, err = io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return
	}
	// Приводимо приватний ключ до формату X25519 (clamping)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

// DH: X25519(shared) = scalarMult(priv, peerPub)
func dh(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	var out [32]byte
	curve25519.ScalarMult(&out, &priv, &peerPub)
	return out, nil
}

// З'єднати кілька DH-виходів у один секрет через HKDF-SHA256
func deriveSessionKey(dhParts [][]byte, info []byte) ([]byte, error) {
	// Об'єднаємо DH частини в буфер
	concat := []byte{}
	for _, p := range dhParts {
		concat = append(concat, p...)
	}
	// Використаємо HKDF(SHA256, ikm=concat) для отримання 32 байт ключа
	hk := hkdf.New(sha256.New, concat, nil, info)
	key := make([]byte, 32)
	_, err := io.ReadFull(hk, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Шифрування AES-256-GCM
func encryptAESGCM(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// Дешифрування AES-256-GCM
func decryptAESGCM(key, nonce, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	return plaintext, err
}

func TestBidirectionalMMM(t *testing.T) {
	// --- СТАТИЧНИЙ КЛЮЧ СЕРВЕРА (згенеровано один раз і зберігається) ---
	serverStaticPriv, serverStaticPub, err := genX25519KeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Println("Server static pub:", hex.EncodeToString(serverStaticPub[:]))

	// --- СИМУЛЯЦІЯ КЛІЄНТА ---
	// Клієнт генерує епхемерний ключ
	clientEphPriv, clientEphPub, err := genX25519KeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Println("Client eph pub:", hex.EncodeToString(clientEphPub[:]))

	// Клієнт відправляє свій clientEphPub серверу.
	// Сервер: для цієї сесії генерує ephemeral ключ
	serverEphPriv, serverEphPub, err := genX25519KeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Println("Server eph pub:", hex.EncodeToString(serverEphPub[:]))

	// Тепер кожна сторона обчислює два DH:
	// A) clientEphPriv <-> serverStaticPub
	// B) clientEphPriv <-> serverEphPub
	// (сервер симетрично обчислює серверEphPriv <-> clientEphPub і serverStaticPriv <-> clientEphPub)

	// --- КЛІЄНТ --- обчислення DH
	dh1_client, err := dh(clientEphPriv, serverStaticPub) // clientEph x serverStatic
	if err != nil {
		panic(err)
	}
	dh2_client, err := dh(clientEphPriv, serverEphPub) // clientEph x serverEph
	if err != nil {
		panic(err)
	}

	// --- СЕРВЕР --- обчислення DH
	dh1_server, err := dh(serverStaticPriv, clientEphPub) // serverStatic x clientEph
	if err != nil {
		panic(err)
	}
	dh2_server, err := dh(serverEphPriv, clientEphPub) // serverEph x clientEph
	if err != nil {
		panic(err)
	}

	// Для надійності перевіримо, що клієнт і сервер отримали ті самі значення
	if !hmac.Equal(dh1_client[:], dh1_server[:]) || !hmac.Equal(dh2_client[:], dh2_server[:]) {
		panic("DH mismatch")
	}

	// Derive final session key (обидві сторони виконують те саме)
	info := []byte("X25519-Signal-simple-v1")
	sessionKeyClient, err := deriveSessionKey([][]byte{dh1_client[:], dh2_client[:]}, info)
	if err != nil {
		panic(err)
	}
	sessionKeyServer, err := deriveSessionKey([][]byte{dh1_server[:], dh2_server[:]}, info)
	if err != nil {
		panic(err)
	}

	fmt.Println("Session key (client):", hex.EncodeToString(sessionKeyClient))
	fmt.Println("Session key (server):", hex.EncodeToString(sessionKeyServer))

	// Симетричне шифрування перевірка
	msg := []byte("Secret message: привіт, перевірка сесії")
	nonce, ct, err := encryptAESGCM(sessionKeyClient, msg)
	if err != nil {
		panic(err)
	}
	pt, err := decryptAESGCM(sessionKeyServer, nonce, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(pt))
	t.Fatal(1)
}
*/
