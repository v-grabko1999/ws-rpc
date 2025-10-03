package wetsock

import (
	"crypto/rand"
	"errors"
	"io"
)

// encryptMessage шифрує (AES-GCM) plain []byte → encrypted []byte (nonce + ciphertext + auth tag)
func (c *codec) encryptMessage(plaintext []byte) ([]byte, error) {
	// стискаємо дані

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := c.gcm.Seal(nonce, nonce, plaintext, nil)
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

	plaintext, err := c.gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return &plaintext, nil
}
