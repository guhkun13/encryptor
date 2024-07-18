package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate AES keys of various lengths and save to file",
}

func main() {
	var generateCmd = &cobra.Command{
		Use:   "gen [outputDir]",
		Short: "Generate AES keys and save to file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			outputDir := args[0]

			numKeys := 100
			keyLength := 16

			// Generate unique keys
			keys, err := generateUniqueKeys(numKeys, keyLength)
			if err != nil {
				fmt.Println("Error generating keys:", err)
				return
			}

			if outputDir == "" {
				fmt.Println("Output file name not provided. Use --output flag to specify the file name.")
				return
			}

			// Save keys to file
			outputFile := outputDir + "/keys.txt"
			if err := saveKeysToFile(outputFile, keys); err != nil {
				fmt.Println("Error saving keys to file:", err)
				return
			}

			fmt.Printf("Generated %d unique keys of length %d bytes and saved to %s\n", numKeys, keyLength, outputFile)
		},
	}

	// Add generateCmd to root command
	rootCmd.AddCommand(generateCmd)

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func generateUniqueKeys(numKeys int, keyLength int) ([]string, error) {
	keys := make([]string, 0, numKeys)
	keySet := make(map[string]struct{})

	keyLength /= 2

	for len(keys) < numKeys {
		key := make([]byte, keyLength)
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}

		keyHex := hex.EncodeToString(key)
		if _, ok := keySet[keyHex]; !ok {
			keySet[keyHex] = struct{}{}
			keys = append(keys, keyHex)
		}
	}

	return keys, nil
}

// saveKeysToFile saves keys into a text file line by line.
func saveKeysToFile(filename string, keys []string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, key := range keys {
		_, err := file.WriteString(key + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}
