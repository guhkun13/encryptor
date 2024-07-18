package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"strings"

	"github.com/guhkun13/encryptor"
)

// Set the output file path
const outputFilePath = ".secret.encrypted.env"

type GenFile struct {
	Len      int
	Type     string
	Filename string
}

var keyFile = GenFile{
	Len:      30,
	Type:     "key",
	Filename: "key.txt",
}

var ivFile = GenFile{
	Len:      10,
	Type:     "iv",
	Filename: "iv.txt",
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

	ivValue := readLineFromFile(*keyDirPath, ivFile.Type, idxIV)
	keyVal := readLineFromFile(*keyDirPath, keyFile.Type, idxKey)

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

		// Write the key and encrypted value to the output file
		_, err = outputFile.WriteString(fmt.Sprintf("%s=%s\n", key, base64.StdEncoding.EncodeToString(encryptedValue)))
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

func readLineFromFile(keyDirPath string, fileType string, lineNumberSearched int) string {
	slog.Info("readLineFromFile")

	slog.Info("param",
		slog.String("keyDirPath", keyDirPath),
		slog.String("fileType", fileType),
		slog.Int("lineNumberSearched", lineNumberSearched),
	)

	filename := keyFile.Filename
	if fileType == ivFile.Type {
		filename = ivFile.Filename
	}
	filename = fmt.Sprintf("%s/%s", keyDirPath, filename)

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return ""
	}
	defer file.Close()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	lineNumber := 1
	var lineX string
	for scanner.Scan() {
		line := scanner.Text()

		if lineNumber == lineNumberSearched {
			lineX = line
			return lineX
		}
		lineNumber++
	}

	return ""
}
