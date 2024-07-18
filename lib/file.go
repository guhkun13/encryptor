package lib

import (
	"bufio"
	"fmt"
	"os"
)

func ReadLineFromFile(filename string, lineNumberSearched int) string {
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
