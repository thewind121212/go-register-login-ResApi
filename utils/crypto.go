package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func EncryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random IV (Initialization Vector)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		fmt.Println("error generating IV:", err)
	}

	// Pad the data to a multiple of the block size
	data = pkcs7Pad(data, aes.BlockSize)

	// Create a CBC mode cipher block
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the data
	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)

	// Prepend the IV to the ciphertext
	ciphertext = append(iv, ciphertext...)

	return ciphertext, nil
}

func DecryptAES(base64Ciphertext string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		fmt.Println("error decoding base64:", err)
	}

	// Extract the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create a CBC mode cipher block
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the data
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	ciphertext = pkcs7Unpad(ciphertext)

	return ciphertext, nil
}

// pkcs7Pad pads the input to a multiple of blockSize using PKCS#7 padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from the input
func pkcs7Unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
