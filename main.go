package encryptor

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
)

const lengthKeys = 50
const lengthIVs = 50

func GetRandomKeyIndex() int {
	return rand.Intn(lengthKeys)
}

func GetRandomIVIndex() int {
	return rand.Intn(lengthIVs)
}

var (
	encKey = []byte("4b5ff54a1bce726b8f50d7c3b1320471")
	iv     = []byte("8f50d7c3b1320471")
)

func main() {

	plainText := "guhkun"
	chiperText, _ := Encrypt([]byte(plainText), encKey, iv)
	slog.Info(plainText)
	slog.Info(string(chiperText))

	plainTextDec, _ := Decrypt(chiperText, encKey, iv)
	slog.Info(string(plainTextDec))
}

// encrypt
func Encrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedPlaintext := padPKCS7(plaintext)

	ciphertext := make([]byte, aes.BlockSize+len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedPlaintext)

	return ciphertext, nil
}

func padPKCS7(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}
	return padtext
}

// decrypt
func Decrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], ciphertext[aes.BlockSize:])

	plaintext, err := unpadPKCS7(ciphertext[aes.BlockSize:])
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func unpadPKCS7(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding: length is zero")
	}
	unpadding := int(data[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, fmt.Errorf("invalid padding: padding byte out of range")
	}
	for i := length - unpadding; i < length; i++ {
		if data[i] != byte(unpadding) {
			return nil, fmt.Errorf("invalid padding: incorrect padding bytes")
		}
	}
	return data[:length-unpadding], nil
}

// read from file
func readLineFromFile(filename string, lineNumber int) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentLine := 0

	for scanner.Scan() {
		currentLine++
		if currentLine == lineNumber {
			return scanner.Text(), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	// If lineNumber is out of range
	return "", fmt.Errorf("line number %d out of range", lineNumber)
}
