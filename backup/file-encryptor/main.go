package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/guhkun13/encryptor"
	"github.com/guhkun13/encryptor/lib"
)

// Set the output file path
const outputFilePath = ".secret.encrypted.env"

type GenFile struct {
	Len      int
	Type     string
	Filename string
}

var keyFile = GenFile{
	Len:      lib.KeyLen,
	Type:     "key",
	Filename: lib.KeyFilename,
}

var ivFile = GenFile{
	Len:      lib.KeyLen,
	Type:     "iv",
	Filename: lib.IVFilename,
}

func getRandomKeyIndex() int {
	return rand.Intn(keyFile.Len) + 1
}

func getRandomIVIndex() int {
	return rand.Intn(ivFile.Len) + 1
}

func main() {
	// Define command-line flags for secret file path
	secretFilePath := flag.String("input", "", "Path to the secret file")
	keyDirPath := flag.String("keyDir", "", "Path to the key directory. can be version")
	flag.Parse()

	// Check if the secret file path is provided
	if *secretFilePath == "" {
		fmt.Println("Error: secret file path is not provided.")
		flag.Usage()
		return
	}

	if *keyDirPath == "" {
		fmt.Println("Error: key dir path is not provided.")
		flag.Usage()
		return
	}

	encryptFile(secretFilePath, keyDirPath)

}

func encryptFile(secretFilePath, keyDirPath *string) {
	// Open the secret file
	file, err := os.Open(*secretFilePath)
	if err != nil {
		fmt.Printf("Error opening secret file: %v\n", err)
		return
	}
	defer file.Close()

	// Create the output file to write the encrypted content
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer outputFile.Close()

	idxKey := getRandomKeyIndex()
	idxIV := getRandomIVIndex()

	ivFilename := fmt.Sprintf("%s/%s", *keyDirPath, ivFile.Filename)
	keyFilename := fmt.Sprintf("%s/%s", *keyDirPath, keyFile.Filename)

	ivValue := lib.ReadLineFromFile(ivFilename, idxIV)
	keyVal := lib.ReadLineFromFile(keyFilename, idxKey)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Split the line into key and value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			// If the line doesn't contain "=", write it as is
			_, err = outputFile.WriteString(line + "\n")
			if err != nil {
				fmt.Printf("Error writing to output file: %v\n", err)
				return
			}
			continue
		}

		key := parts[0]
		value := parts[1]

		fmt.Println("plaintext value", value)
		fmt.Println("keyVal", keyVal)
		fmt.Println("ivVal", ivValue)

		// Encrypt the value
		encryptedValue, err := encryptor.Encrypt([]byte(value), []byte(keyVal), []byte(ivValue))
		if err != nil {
			fmt.Printf("Error encrypting data: %v\n", err)
			return
		}

		newVal := base64.StdEncoding.EncodeToString(encryptedValue)
		fmt.Println("encryptedValue", encryptedValue)
		fmt.Println("newVal", newVal)

		// Write the key and encrypted value to the output file
		_, err = outputFile.WriteString(fmt.Sprintf("%s=%s\n", key, newVal))
		if err != nil {
			fmt.Printf("Error writing to output file: %v\n", err)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading secret file: %v\n", err)
		return
	}

	fmt.Println("File successfully encrypted")
	fmt.Printf("key combination was [%s-%d-%d] \n", *keyDirPath, idxKey, idxIV)
}
