package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
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

func ReadPayloadToFile(filepath string, data []byte) (bool, error) {
	fileName := filepath // Specify your file name

	// Check if file exists
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		// Create file if it does not exist
		file, err := os.Create(fileName)
		if err != nil {
			fmt.Println("Error creating file:", err)
			return false, nil
		}
		file.Close() // Close the file after creating it
	}

	// Open the file for writing
	file, err := os.OpenFile(fileName, os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return false, nil
	}
	defer file.Close() // Ensure file is closed after writing

	// Write to the file
	_, err = file.Write(data)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return false, nil
	}

	fmt.Println("File written successfully")
	return true, nil

}

// ReadFileAndExtractComponents reads data from the file, extracts the key, IV, and payload.
func ReadFileAndExtractComponents(filePath string) ([]byte, []byte, []byte, error) {
	// Read the entire file into a byte slice.
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Ensure the file has at least 48 bytes for the key and IV.
	if len(data) < 48 {
		return nil, nil, nil, fmt.Errorf("file content is too short")
	}

	// Extract the key, IV, and payload from the data.
	key := data[:32]
	iv := data[32:48]
	payload := data[48:]

	return key, iv, payload, nil
}

func ReadFileWithoutComponents(filePath string) ([]byte, error) {
	// Read the entire file into a byte slice.
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	// read the file to a byte slice
	return data, nil
}
