package awsfuncs

import (
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"go-kms-s3/encryption"
	"io/ioutil"
	"os"
)

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
