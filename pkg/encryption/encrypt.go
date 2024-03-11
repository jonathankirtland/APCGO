package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
)

func Aes256(key, data []byte) ([]byte, []byte, error) {
	length := len(key)
	if !(length == 16 || length == 24 || length == 32) {
		return nil, nil, errors.New("[!] Bad AES Key")
	}
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, nil, err
	}
	data = pad(data)
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext[aes.BlockSize:], iv, nil
}

func pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padBytes...)
}

func EncryptPayload(key string, payload []byte) ([]byte, []byte, []byte, bool) {
	var value []byte
	var err error
	var iv []byte
	value, iv, err = Aes256([]byte(key), payload)
	if err != nil {
		log.Fatal("[x] Error: Aes256 encryption failed.", err)
		return nil, nil, nil, false
	}
	//valueString := BytesToHexArray(value)
	//ivString := BytesToHexArray(iv)
	/*
		print("\nvar payload []byte = []byte(\n\"")
		print(valueString)
		print("\")\n")

		println()

		print("\nvar iv []byte = []byte(\n\"")
		print(ivString)
		print("\")\n")

		println()

		print("\nvar key []byte = []byte(\n\"")
		print(BytesToHexArray([]byte(key)))
		print("\")\n")
	*/
	return value, iv, []byte(key), true
}

func BytesToHexArray(shellCode []byte) string {
	var stringsArray []string
	for i, b := range shellCode {
		if i+1 == len(shellCode) {
			stringsArray = append(stringsArray, fmt.Sprintf("\\x%02x", b))

		} else {
			stringsArray = append(stringsArray, fmt.Sprintf("\\x%02x", b))
		}
	}
	result := strings.Join(stringsArray, "")
	return result
}
