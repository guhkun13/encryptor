package encryptor

import (
	"bufio"
	"fmt"
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
