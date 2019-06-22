package crypto

import (
	"crypto/aes"
	"fmt"
)

// ECB mode key is 16 bytes
func validKey(key []byte) bool {
	if len(key) == 16 {
		return true
	}

	return false
}

// ECBDecrypt ECB encrypt
func ECBDecrypt(crypted, key []byte) ([]byte, error) {
	if !validKey(key) {
		return nil, fmt.Errorf("invalid key length, expected %d, actual %d", 16, len(key))
	}
	if len(crypted) < 1 {
		return nil, fmt.Errorf("ECB decrypt length is 0, need data")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(crypted)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid src length, expected length which can be divided by 16, actual %d", len(crypted))
	}

	var dst []byte
	tmpData := make([]byte, block.BlockSize())

	for index := 0; index < len(crypted); index += block.BlockSize() {
		block.Decrypt(tmpData, crypted[index:index+block.BlockSize()])
		dst = append(dst, tmpData...)
	}

	dst, err = PKCS5UnPadding(dst)
	if err != nil {
		return nil, err
	}

	// fmt.Println("source bytes :", dst, "\n", "source string :", string(dst))

	return dst, nil
}

// ECBEncrypt ECB decrypt
func ECBEncrypt(src, key []byte) ([]byte, error) {
	if !validKey(key) {
		return nil, fmt.Errorf("invalid key length, expected %d, actual %d", 16, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < 1 {
		return nil, fmt.Errorf("ECB encrypt src length is 0, need data")
	}

	// mode := NewECBEncrypter(block)
	src = PKCS5Padding(src, block.BlockSize())

	if len(src)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid src length, expected length which can be divided by 16, actual %d", len(src))
	}

	var dst []byte
	tmpData := make([]byte, block.BlockSize())

	for index := 0; index < len(src); index += block.BlockSize() {
		block.Encrypt(tmpData, src[index:index+block.BlockSize()])
		dst = append(dst, tmpData...)
	}

	// fmt.Println("base64 result:", base64.StdEncoding.EncodeToString(dst))

	return dst, nil
}
