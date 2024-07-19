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

type KeyFile struct {
	Len      int
	Filename string
}

var keyFile = KeyFile{
	Len:      lib.KeyLen,
	Filename: lib.KeyFilename,
}

func main() {
	// Define command-line flags for secret file path
	secretFilePath := flag.String("input", "", "Path to the secret file")
	flag.Parse()

	// Check if the secret file path is provided
	if *secretFilePath == "" {
		fmt.Println("Error: secret file path is not provided.")
		flag.Usage()
		return
	}

	encryptFile(secretFilePath)

}

func getRandVal() int {
	return rand.Intn(len(encryptor.SecretKeys)) + 1
}

func encryptFile(secretFilePath *string) {
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

	idxKey := getRandVal()
	idxIV := getRandVal()

	keyVal := encryptor.SecretKeys[idxKey]
	ivValue := encryptor.SecretKeys[idxIV]

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

		// Encrypt the value
		encryptedValue, err := encryptor.Encrypt([]byte(value), []byte(keyVal), []byte(ivValue))
		if err != nil {
			fmt.Printf("Error encrypting data: %v\n", err)
			return
		}
		delim := lib.EncodingDelimiter

		newVal := base64.StdEncoding.EncodeToString(encryptedValue)
		newVal = fmt.Sprintf("%d%s%s%s%d", idxKey, delim, newVal, delim, idxIV)

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
	fmt.Printf("key combination was [%d-%d] \n", idxKey, idxIV)
}
