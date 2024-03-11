package stalling

import (
	"fmt"
	"io/ioutil"
	"os"
)

// isPrime checks if a number is prime
func isPrime(n int) bool {
	if n <= 1 {
		return false
	}
	for i := 2; i*i <= n; i++ {
		if n%i == 0 {
			return false
		}
	}
	return true
}

// calculatePrimes finds all prime numbers up to a certain limit
func CalculatePrimes(limit int) {
	for num := 1; num <= limit; num++ {
		if isPrime(num) {
			// Uncomment the following line to see the primes as they are found
			// fmt.Println(num)
		}
	}
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
