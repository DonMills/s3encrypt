package awsfuncs

import (
	"fmt"
	"testing"
)

func TestKMSGenerateDecrypt(t *testing.T) {
	cipherkey, plainkey := GenerateEnvKey("504dac3b-a6d0-4579-8aa2-cac51ca6d489", "testkey")
	fmt.Printf("CiphertextBlob: %v\n", cipherkey)
	fmt.Printf("PlaintextKey: %v\n", plainkey)
	deckey := decryptkey(cipherkey, "testkey")
	fmt.Printf("DecryptedKey: %v\n", deckey)
	if string(plainkey) != string(deckey) {
		t.Error("Key Decryption failed! Error in key generate/decrypt functions")
	}
}
