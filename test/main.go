package main

import (
	"fmt"

	"github.com/guhkun13/encryptor"
)

func main() {
	keyComb := "143-56"

	encodedText := "AAAAAAAAAAAAAAAAAAAAAPUcnhdqRNurAunESPPD5NqiUaVOmStq5o6WcA9j+m6d"
	plainText, err := encryptor.DecryptByKeyCombination(keyComb, encodedText)
	if err != nil {
		fmt.Errorf("failed to decrypt : %v", err.Error())
		return
	}
	fmt.Println("encodedText: ", encodedText)
	fmt.Println("plainText: ", plainText)
}
