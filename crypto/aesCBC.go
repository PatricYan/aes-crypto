package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	// CommonKey is 16, 24, 32 bytes
	CommonKey = []byte("1234567890123456")
)

// CBCEncrypt AES CBC mode encryption
func CBCEncrypt(rawData []byte) ([]byte, error) {
	block, err := aes.NewCipher(CommonKey)
	if err != nil {
		return nil, err
	}

	rawData = PKCS7Padding(rawData, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(rawData))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext[aes.BlockSize:], rawData)
	return ciphertext, nil
}

// CBCDecrypt AES CBC mode decryption
func CBCDecrypt(encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(CommonKey)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < aes.BlockSize {
		return nil, errors.New("encrypted data too short")
	}

	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]
	if len(encryptedData)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encryptData can not be divided by %d", aes.BlockSize)
	}

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(encryptedData, encryptedData)
	encryptedData, err = PKCS7UnPadding(encryptedData)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}
