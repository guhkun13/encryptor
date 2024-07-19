package main

import (
	"fmt"

	"github.com/guhkun13/encryptor"
)

func main() {
	secretKey := "281.AAAAAAAAAAAAAAAAAAAAADnjJhkehplqKowjWwIoYeJ9hvvSWW8oHiXCp+2KDH3F.279"
	plainText, err := encryptor.DecryptByKeyCombination(secretKey)
	if err != nil {
		fmt.Errorf("failed to decrypt : %v", err.Error())
		return
	}
	fmt.Println("secretKey: ", secretKey)
	fmt.Println("plainText: ", plainText)
}
