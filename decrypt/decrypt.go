package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

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
