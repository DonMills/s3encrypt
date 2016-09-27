// Package awsfuncs contains all the code that deals directly with AWS services
package awsfuncs

import (
	"DonMills/go-kms-s3/encryption"
	"DonMills/go-kms-s3/errorhandle"
	"bytes"

	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
)

var s3svc *s3.S3
var kmssvc *kms.KMS

func init() {
	s3svc = s3.New(session.New())
	kmssvc = kms.New(session.New())
}

//GenerateEnvKey This function is used to generate KMS encryption keys for
//envelope encryption
func GenerateEnvKey(cmkID string, context string) ([]byte, []byte) {
	genparams := &kms.GenerateDataKeyInput{
		KeyId: aws.String(cmkID),
		EncryptionContext: map[string]*string{
			"Application": aws.String(context),
		},
		KeySpec: aws.String("AES_256"),
	}
	resp, err := kmssvc.GenerateDataKey(genparams)
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
	params := &s3.GetObjectInput{
		Bucket: aws.String(bucket),      // Required
		Key:    aws.String(remfilename), // Required
	}
	file, err := s3svc.GetObject(params)

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
	keyparams := &kms.DecryptInput{
		CiphertextBlob: output, // Required
		EncryptionContext: map[string]*string{
			"Application": aws.String(context),
		},
	}

	plainkey, err := kmssvc.Decrypt(keyparams)
	if err != nil {
		errorhandle.AWSError(err)
	}
	decodelen := base64.StdEncoding.DecodedLen(len(plainkey.Plaintext))
	decodedplainkey := make([]byte, decodelen)
	base64.StdEncoding.Decode(decodedplainkey, plainkey.Plaintext)
	return plainkey.Plaintext
}

//putenckey places the encrypted key in AWS S3.
func putenckey(key []byte, remfilename string, bucket string, sse string) {
	var params *s3.PutObjectInput

	encodelen := base64.StdEncoding.EncodedLen(len(key))
	enckey := make([]byte, encodelen)
	base64.StdEncoding.Encode(enckey, key)

	if sse != "nil" {
		params = &s3.PutObjectInput{
			Bucket:               aws.String(bucket),               // Required
			Key:                  aws.String(remfilename + ".key"), // Required
			Body:                 bytes.NewReader(enckey),
			ServerSideEncryption: aws.String(sse),
		}
	} else {
		params = &s3.PutObjectInput{
			Bucket: aws.String(bucket),               // Required
			Key:    aws.String(remfilename + ".key"), // Required
			Body:   bytes.NewReader(enckey),
		}
	}
	_, err := s3svc.PutObject(params)
	if err != nil {
		errorhandle.AWSError(err)
	}
}

//PutEncKey puts the encrypted key in AWS S3 with no SSE
func PutEncKey(key []byte, remfilename string, bucket string) {
	sse := "nil"
	putenckey(key, remfilename, bucket, sse)
}

//PutEncKeyS3SSE puts the encrypted key in AWS S3 with S3 managed SSE
func PutEncKeyS3SSE(key []byte, remfilename string, bucket string) {
	sse := "AES_256"
	putenckey(key, remfilename, bucket, sse)
}

//PutEncKeyKMSSSE puts the encrypted key in AWS S3 with KMS managed SSE
func PutEncKeyKMSSSE(key []byte, remfilename string, bucket string) {
	sse := "aws:kms"
	putenckey(key, remfilename, bucket, sse)
}

//FetchFile This function is used to fetch the decrypted file from S3 and grab
//all pertinent metatdata (IV, key)
func FetchFile(remfilename string, bucket string) ([]byte, []byte, []byte) {
	params := &s3.GetObjectInput{
		Bucket: aws.String(bucket),      // Required
		Key:    aws.String(remfilename), // Required
	}
	file, err := s3svc.GetObject(params)

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
