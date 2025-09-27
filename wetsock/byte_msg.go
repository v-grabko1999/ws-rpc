package wetsock

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	zstdDecoderPool = sync.Pool{
		New: func() any {
			dec, err := zstd.NewReader(nil)
			if err != nil {
				log.Panicf("wetsock: не вдалося створити zstd.Decoder: %v", err)
			}
			return dec
		},
	}

	zstdEncoderPool = sync.Pool{
		New: func() any {
			// Максимальний рівень стиснення
			enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
			if err != nil {
				log.Panicf("wetsock: не вдалося створити zstd.Encoder: %v", err)
			}
			return enc
		},
	}
)

// encryptMessage шифрує (AES-GCM) plain []byte → encrypted []byte (nonce + ciphertext + auth tag)
func (c *codec) encryptMessage(plaintext []byte) ([]byte, error) {
	// стискаємо дані
	enc := zstdEncoderPool.Get().(*zstd.Encoder)
	defer zstdEncoderPool.Put(enc)

	compressed := enc.EncodeAll(plaintext, make([]byte, 0, enc.MaxEncodedSize(len(plaintext))))

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := c.gcm.Seal(nonce, nonce, compressed, nil)
	return ciphertext, nil
}

// decryptMessage розшифровує []byte (nonce + ciphertext + tag) → plain []byte
func (c *codec) decryptMessage(ciphertext []byte) (*[]byte, error) {
	nonceSize := c.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext is too short")
	}
	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	compressed, err := c.gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	dec := zstdDecoderPool.Get().(*zstd.Decoder)
	defer zstdDecoderPool.Put(dec)

	// розпакування
	plaintext, err := dec.DecodeAll(compressed, nil)
	if err != nil {
		return nil, err
	}

	return &plaintext, nil
}
