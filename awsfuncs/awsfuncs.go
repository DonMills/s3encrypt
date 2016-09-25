package awsfuncs

import (
	"DonMills/go-kms-s3/encryption"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
)

//GenerateKey This function is used to generate KMS encryption keys
func GenerateKey(cmkID string, context string) ([]byte, []byte) {
	keygensvc := kms.New(session.New())
	genparams := &kms.GenerateDataKeyInput{
		KeyId: aws.String(cmkID),
		EncryptionContext: map[string]*string{
			"Application": aws.String(context),
		},
	}
	resp, err := keygensvc.GenerateDataKey(genparams)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			fmt.Println(awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
			if reqErr, ok := err.(awserr.RequestFailure); ok {
				fmt.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
				os.Exit(1)
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	fmt.Println(resp)
	return nil, nil
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
		if awsErr, ok := err.(awserr.Error); ok {
			// Generic AWS error with Code, Message, and original error (if any)
			fmt.Println(awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
			if reqErr, ok := err.(awserr.RequestFailure); ok {
				// A service error occurred
				fmt.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
				os.Exit(1)
			}
		} else {
			// This case should never be hit, the SDK should always return an
			// error which satisfies the awserr.Error interface.
			fmt.Println(err.Error())
		}
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
		if awsErr, ok := err.(awserr.Error); ok {
			fmt.Println(awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
			if reqErr, ok := err.(awserr.RequestFailure); ok {
				fmt.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
				os.Exit(1)
			}
		} else {
			fmt.Println(err.Error())
			os.Exit(1)
		}
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
		if awsErr, ok := err.(awserr.Error); ok {
			fmt.Println(awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
			if reqErr, ok := err.(awserr.RequestFailure); ok {
				fmt.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
				os.Exit(1)
			}
		} else {
			fmt.Println(err.Error())
			os.Exit(1)
		}
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
