package encryption

import (
	"DonMills/go-kms-s3/padding"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

//BlockSize Export this value (which is always 16 lol) to other packages so they don't need
//to import crypto/aes
var BlockSize = aes.BlockSize

//ECBDecrypt This function does the ECB decryption of the stored data encryption key
//with the KMS generated envelope key
func ECBDecrypt(ciphertext []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	bs := aes.BlockSize
	if len(ciphertext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}

	i := 0
	plaintext := make([]byte, len(ciphertext))
	finalplaintext := make([]byte, len(ciphertext))
	for len(ciphertext) > 0 {
		cipher.Decrypt(plaintext, ciphertext)
		ciphertext = ciphertext[bs:]
		decryptedBlock := plaintext[:bs]
		for index, element := range decryptedBlock {
			finalplaintext[(i*bs)+index] = element
		}
		i++
		plaintext = plaintext[bs:]
	}
	finalplaintextunpad := padding.Unpad(finalplaintext)
	return finalplaintextunpad
}

//ECBEncrypt This function encrypts the data encryption key with the
//KMS generated envelope key
func ECBEncrypt(plaintext []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	bs := aes.BlockSize
	i := 0
	paddedPlain := padding.Pad(plaintext)
	ciphertext := make([]byte, len(paddedPlain))
	finalciphertext := make([]byte, len(paddedPlain))
	for len(paddedPlain) > 0 {
		cipher.Encrypt(ciphertext, paddedPlain)
		paddedPlain = paddedPlain[bs:]
		encryptedBlock := ciphertext[:bs]
		for index, element := range encryptedBlock {
			finalciphertext[(i*bs)+index] = element
		}
		i++
		ciphertext = ciphertext[bs:]
	}
	return finalciphertext
}

//Decryptfile This function uses the decrypted data encryption key and the
//retrived IV from the S3 metadata to decrypt the data file
func Decryptfile(data []byte, iv []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return padding.Unpad(data)
}

//Encryptfile This function uses the provided data encryption key and generates
//an IV to encrypt the data file
func Encryptfile(data []byte, key []byte) ([]byte, []byte) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		panic("There was an IV generation error")
	}
	pmessage := padding.Pad(data)
	ciphertext := make([]byte, len(pmessage))
	c, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(c, iv)
	mode.CryptBlocks(ciphertext, pmessage)
	return ciphertext, iv
}

//generatedatakey Does what's on the tin, generates the data encryption key
func generatedatakey() []byte {
	key := make([]byte, 16)
	rand.Read(key)
	return key
}
