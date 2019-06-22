package crypto

import (
	"bytes"
	"errors"
)

// PKCS7Padding add fields
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding return origin data
func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])
	if length < unpadding {
		return nil, errors.New("invalid unpadding length")
	}

	return origData[:(length - unpadding)], nil
}

// PKCS5Padding pad length
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS5UnPadding remove padded length
func PKCS5UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])

	if length < unpadding {
		return nil, errors.New("invalid unpadding length")
	}

	return origData[:(length - unpadding)], nil
}
