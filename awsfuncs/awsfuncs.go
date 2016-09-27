// Package awsfuncs contains all the code that deals directly with AWS services
package awsfuncs

import (
	"DonMills/go-kms-s3/encryption"
	"DonMills/go-kms-s3/errorhandle"

	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
)

//GenerateEnvKey This function is used to generate KMS encryption keys for
//envelope encryption
func GenerateEnvKey(cmkID string, context string) ([]byte, []byte) {
	keygensvc := kms.New(session.New())
	genparams := &kms.GenerateDataKeyInput{
		KeyId: aws.String(cmkID),
		EncryptionContext: map[string]*string{
			"Application": aws.String(context),
		},
		KeySpec: aws.String("AES_256"),
	}
	resp, err := keygensvc.GenerateDataKey(genparams)
	if err != nil {
		errorhandle.AWSError(err)
	}
	plainkey := resp.Plaintext
	cipherkey := resp.CiphertextBlob
	return cipherkey, plainkey
}

//FetchKey This function is used to fetch a saved encrypted key from S3 and
//decrypt it with KMS
func FetchKey(remfilename string, bucket string, context string) []byte {
	svc := s3.New(session.New())
	params := &s3.GetObjectInput{
		Bucket: aws.String(bucket),      // Required
		Key:    aws.String(remfilename), // Required
	}
	file, err := svc.GetObject(params)

	if err != nil {
		errorhandle.AWSError(err)
	}
	decode := base64.NewDecoder(base64.StdEncoding, file.Body)
	output, _ := ioutil.ReadAll(decode)
	decryptedkey := decryptkey(output, context)
	return decryptedkey
}

//decryptkey does the actual KMS decryption of the stored key
func decryptkey(output []byte, context string) []byte {
	service := kms.New(session.New())

	keyparams := &kms.DecryptInput{
		CiphertextBlob: output, // Required
		EncryptionContext: map[string]*string{
			"Application": aws.String(context),
		},
	}

	plainkey, err := service.Decrypt(keyparams)
	if err != nil {
		errorhandle.AWSError(err)
	}
	decodelen := base64.StdEncoding.DecodedLen(len(plainkey.Plaintext))
	decodedplainkey := make([]byte, decodelen)
	base64.StdEncoding.Decode(decodedplainkey, plainkey.Plaintext)
	return plainkey.Plaintext
}

//FetchFile This function is used to fetch the decrypted file from S3 and grab
//all pertinent metatdata (IV, key)
func FetchFile(remfilename string, bucket string) ([]byte, []byte, []byte) {
	svc := s3.New(session.New())
	params := &s3.GetObjectInput{
		Bucket: aws.String(bucket),      // Required
		Key:    aws.String(remfilename), // Required
	}
	file, err := svc.GetObject(params)

	if err != nil {
		errorhandle.AWSError(err)
	}

	data, _ := ioutil.ReadAll(file.Body)
	encodeiv := *file.Metadata["X-Amz-Iv"]
	s3encodekey := *file.Metadata["X-Amz-Key"]
	iv, _ := base64.StdEncoding.DecodeString(encodeiv)
	s3key, _ := base64.StdEncoding.DecodeString(s3encodekey)
	if (len(data) % encryption.BlockSize) != 0 {
		fmt.Println("There is a size issue!")
	}
	return data, iv, s3key
}
