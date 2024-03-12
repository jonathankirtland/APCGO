package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// DecryptAES decrypts a ciphertext using the given key and IV
// The ciphertext must be a multiple of the block size
func DecryptAES(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	// Make a copy of the ciphertext to avoid modifying the original slice
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	mode.CryptBlocks(plaintext, plaintext)
	return plaintext, nil
}
