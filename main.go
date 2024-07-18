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

func DecryptByKeyCombination(keyComb string, encodedText string) (string, error) {
	fmt.Println("DecryptByKeyCombination")
	fmt.Println("keyComb:", keyComb)
	keyCombs := strings.Split(keyComb, "-")
	dirPath := keyCombs[0]
	keyIndex, err := strconv.Atoi(keyCombs[1])
	if err != nil {
		fmt.Errorf("failed to convert string to integer on keyIndex : %s", err.Error())
		return "", err
	}

	ivIndex, err := strconv.Atoi(keyCombs[2])
	if err != nil {
		fmt.Errorf("failed to convert string to integer on ivIndex : %s", err.Error())
		return "", err
	}

	keyFilename := fmt.Sprintf("%s/%s", dirPath, lib.KeyFilename)

	keyVal := lib.ReadLineFromFile(keyFilename, keyIndex)
	ivVal := lib.ReadLineFromFile(keyFilename, ivIndex)

	encryptedValue, err := base64.StdEncoding.DecodeString(encodedText)
	if err != nil {
		fmt.Errorf("failed to StdEncoding.DecodeString : %s", err.Error())
		return "", err
	}

	plainText, err := Decrypt(encryptedValue, []byte(keyVal), []byte(ivVal))
	if err != nil {
		fmt.Println("error cuk")
		fmt.Println(err.Error())
		return "", err
	}

	return string(plainText), nil
}
