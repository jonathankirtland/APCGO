package main

import (
	"crypto/rand"
	"fmt"
	"github.com/jonathankirtland/APCGO/pkg/encryption"
	"io"
)

type Field struct {
	Values map[string]string
}

func main() {
	keySize := 32 // for AES-256
	key := make([]byte, keySize)
	// Generate a random key.
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err) // Handle error properly in real use.
	}

	var data []byte

	// fill data with payload file
	data, err := encryption.ReadFileWithoutComponents("payload.bin")

	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	value, iv, key, _ := encryption.EncryptPayload(string(key), data)

	var bytes []byte

	bytes = append(bytes, key...)
	bytes = append(bytes, iv...)
	bytes = append(bytes, value...)

	result := fmt.Sprintf("Length of key %d, length of iv %d, length of payload %d\n", len(key), len(iv), len(value))

	print(result)

	encryption.ReadPayloadToFile("payload/payload.bin", bytes)

}
