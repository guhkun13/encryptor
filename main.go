package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/guhkun13/encryptor/lib"
)

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

func decomposeSecret(secretKey string) (keyIdx, ivIdx int, encText string) {
	temp := strings.Split(secretKey, lib.EncodingDelimiter)
	keyIdx, _ = strconv.Atoi(temp[0])
	ivIdx, _ = strconv.Atoi(temp[2])
	encText = temp[1]

	return
}

func DecryptByKeyCombination(secretKey string) (string, error) {
	// fmt.Println("DecryptByKeyCombination")
	// fmt.Println("secretKey = ", secretKey)

	keyIndex, ivIndex, encodedText := decomposeSecret(secretKey)
	keyVal := SecretKeys[keyIndex]
	ivVal := SecretKeys[ivIndex]

	// fmt.Println("keyIndex = ", keyIndex)
	// fmt.Println("ivIndex = ", ivIndex)
	// fmt.Println("keyVal = ", keyVal)
	// fmt.Println("ivVal = ", ivVal)
	// fmt.Println("encodedText = ", encodedText)

	encryptedValue, err := base64.StdEncoding.DecodeString(encodedText)
	if err != nil {
		fmt.Println("failed to StdEncoding.DecodeString ", err.Error())
		return "", err
	}
	// fmt.Println("encryptedValue", encryptedValue)

	plainText, err := Decrypt(encryptedValue, []byte(keyVal), []byte(ivVal))
	if err != nil {
		fmt.Println("error brow", err.Error())
		return "", err
	}
	// fmt.Println("plainText", plainText)

	return string(plainText), nil
}
