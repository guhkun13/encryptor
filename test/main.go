package main

import (
	"fmt"

	"github.com/guhkun13/encryptor"
)

func main() {
	keyComb := "env/local/guhkun-1-6"

	encodedText := "AAAAAAAAAAAAAAAAAAAAAK1VyBpYTtDitwctdyRN4Ud4vhn+z4XZLjj5Ced7JZb5"
	plainText, err := encryptor.DecryptByKeyCombination(keyComb, encodedText)
	if err != nil {
		fmt.Errorf("failed to decrypt : %v", err.Error())
		return
	}
	fmt.Println("encodedText: ", encodedText)
	fmt.Println("plainText: ", plainText)
}
