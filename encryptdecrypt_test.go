package main

import (
	"fmt"
	"testing"
)

func TestEncryptDecryptCBCOne(t *testing.T) {
	data := []byte("Test String one")
	fmt.Printf("Original Data: %s\n", string(data))
	key := generateDataKey()
	ctext, iv := encryptFile(data, key)
	result := decryptFile(ctext, iv, key)
	fmt.Printf("Decrypted Data: %s\n", string(result))
	if string(data) != string(result) {
		t.Error("Decryption failed!  Error in Decryptfile/Encryptfile functions")
	}
}

func TestEncryptDecryptCBCTwo(t *testing.T) {
	data := []byte("abcd1234efgh5678")
	fmt.Printf("Original Data: %s\n", string(data))
	key := generateDataKey()
	ctext, iv := encryptFile(data, key)
	result := decryptFile(ctext, iv, key)
	fmt.Printf("Decrypted Data: %s\n", string(result))
	if string(data) != string(result) {
		t.Error("Decryption failed!  Error in Decryptfile/Encryptfile functions")
	}
}
func TestEncryptDecryptecbOne(t *testing.T) {
	data := []byte("Test data string dos")
	fmt.Printf("Original Data: %s\n", string(data))
	key := generateDataKey()
	ctext := ecbEncrypt(data, key)
	result := ecbDecrypt(ctext, key)
	fmt.Printf("Decrypted Data: %s\n", string(result))
	if string(data) != string(result) {
		t.Error("Decryption failed!  Error in ecb_decrypt/ECB_encrypt functions")
	}
}
func TestEncryptDecryptecbTwo(t *testing.T) {
	data := []byte("abcd1234efgh5678")
	fmt.Printf("Original Data: %s\n", string(data))
	key := generateDataKey()
	ctext := ecbEncrypt(data, key)
	result := ecbDecrypt(ctext, key)
	fmt.Printf("Decrypted Data: %s\n", string(result))
	if string(data) != string(result) {
		t.Error("Decryption failed!  Error in ecb_decrypt/ECB_encrypt functions")
	}
}
