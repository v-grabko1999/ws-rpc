package wetsock

import (
	"crypto/rand"
	"errors"
	"io"
	"runtime"
	"sync"

	"github.com/klauspost/compress/zstd"

)

var (
	// пул указателей на срезы
	bufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 0, 1<<20) // 1MiB начальной ёмкости
			return &b
		},
	}

	decryptPool = sync.Pool{
		New: func() any {
			b := make([]byte, 0, 1<<20) // или ваше среднее
			return &b
		},
	}

	dec, _ = zstd.NewReader(
		nil,
		zstd.WithDecoderConcurrency(runtime.NumCPU()),
	)
	enc, _ = zstd.NewWriter(
		nil,
		zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithEncoderConcurrency(runtime.NumCPU()),
	)
)

func (c *codec) encryptMessage(plaintext []byte) (*[]byte, error) {
	// 1) Получаем указатель на []byte из пула и сбрасываем длину
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]

	// 2) Расчет точной ёмкости: nonce + zstd.MaxEncodedSize + GCM Overhead
	need := c.gcm.NonceSize() + enc.MaxEncodedSize(len(plaintext)) + c.gcm.Overhead()
	if cap(buf) < need {
		buf = make([]byte, 0, need)
	}

	// 3) Генерируем nonce на стеке
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	buf = append(buf, nonce[:]...)

	// 4) Сжимаем прямо в buf
	buf = enc.EncodeAll(plaintext, buf)

	// 5) Шифруем: Seal допишет ciphertext+tag после nonce+compressed
	buf = c.gcm.Seal(buf[:c.gcm.NonceSize()], nonce[:], buf[c.gcm.NonceSize():], nil)

	// 6) Сохраняем новый срез в указателе
	*bufPtr = buf
	return bufPtr, nil
}

// decryptMessage теперь возвращает *([]byte)
func (c *codec) decryptMessage(ct []byte) (*[]byte, error) {
	nonceSize := c.gcm.NonceSize()
	if len(ct) < nonceSize {
		return nil, errors.New("ciphertext is too short")
	}
	nonce, data := ct[:nonceSize], ct[nonceSize:]

	// Получаем указатель на буфер
	bufPtr := decryptPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]

	// Резервируем нужный cap
	need := len(data) - c.gcm.Overhead()
	if cap(buf) < need {
		buf = make([]byte, 0, need)
	}

	// 1) Дешифруем в buf
	decryptedCompressed, err := c.gcm.Open(buf, nonce, data, nil)
	if err != nil {
		*bufPtr = (*bufPtr)[:0]
		decryptPool.Put(bufPtr)
		return nil, err
	}

	// 2) Распаковываем в тот же буфер
	//    (или в новый пуловый, если нужен другой)
	out := (*bufPtr)[:0]
	plaintext, err := dec.DecodeAll(decryptedCompressed, out)
	if err != nil {
		*bufPtr = (*bufPtr)[:0]
		decryptPool.Put(bufPtr)
		return nil, err
	}

	// Сохраняем распакованный срез в указателе и возвращаем
	*bufPtr = plaintext
	return bufPtr, nil
}
