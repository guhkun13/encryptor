package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

const TypeKey = "key"
const TypeIV = "iv"

var rootCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate AES keys of various lengths and save to file",
}

func main() {
	var generateCmd = &cobra.Command{
		Use:   "gen [keyType] [numKeys] [keyLength]",
		Short: "Generate AES keys and save to file",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			keyType := args[0]

			numKeys, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Println("Invalid input for number of keys. Please provide a valid integer.")
				return
			}

			keyLength, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Println("Invalid input for key length. Please provide a valid integer.")
				return
			}

			// Validate key type
			if !isValidKeyType(keyType) {
				fmt.Println("Invalid key type. Supported value are [key, iv]")
				return
			}

			// Validate key length
			if !isValidKeyLength(keyLength) {
				fmt.Println("Invalid key length. Supported lengths are 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.")
				return
			}

			// Generate unique keys
			keys, err := generateUniqueKeys(keyType, numKeys, keyLength)
			if err != nil {
				fmt.Println("Error generating keys:", err)
				return
			}

			outputFile := keyType + ".txt"
			// outputFile, _ := cmd.Flags().GetString("output")
			// if outputFile == "" {
			// 	fmt.Println("Output file name not provided. Use --output flag to specify the file name.")

			// 	return
			// }

			// Save keys to file
			if err := saveKeysToFile(outputFile, keys); err != nil {
				fmt.Println("Error saving keys to file:", err)
				return
			}

			fmt.Printf("Generated %d unique keys of length %d bytes and saved to %s\n", numKeys, keyLength, outputFile)
		},
	}

	// Add flag for output file
	// generateCmd.Flags().StringP("output", "o", "keys.txt", "Output file name to save generated keys")

	// Add generateCmd to root command
	rootCmd.AddCommand(generateCmd)

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func generateUniqueKeys(keyType string, numKeys int, keyLength int) ([]string, error) {
	keys := make([]string, 0, numKeys)
	keySet := make(map[string]struct{})

	// if keyType == TypeIV {
	keyLength /= 2
	// }

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

func isValidKeyType(keyType string) bool {
	switch keyType {
	case TypeKey, TypeIV:
		return true
	default:
		return false
	}
}

func isValidKeyLength(keyLength int) bool {
	switch keyLength {
	case 16, 24, 32:
		return true
	default:
		return false
	}
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
