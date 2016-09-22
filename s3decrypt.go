package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"os"
	"encoding/base64"
	"io/ioutil"
	"./encryption"
	)



func fetchkey(remfilename string, bucket string, context string) []byte {
  svc := s3.New(session.New())
  params := &s3.GetObjectInput{
    Bucket:                     aws.String(bucket), // Required
    Key:                        aws.String(remfilename),  // Required
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
	decode := base64.NewDecoder(base64.StdEncoding,file.Body)
	output,_ := ioutil.ReadAll(decode)

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
			os.Exit(1)
		}
	}
	decodelen := base64.StdEncoding.DecodedLen(len(plainkey.Plaintext))
	decodedplainkey := make([]byte, decodelen)
	base64.StdEncoding.Decode(decodedplainkey,plainkey.Plaintext)
  return plainkey.Plaintext
}

func fetchfile(remfilename string, bucket string) ([]byte,[]byte,[]byte) {
  svc := s3.New(session.New())
  params := &s3.GetObjectInput{
    Bucket:                     aws.String(bucket), // Required
    Key:                        aws.String(remfilename),  // Required
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
			os.Exit(1)
		}
}

	//decode := base64.NewDecoder(base64.StdEncoding,file.Body)
	data,_ := ioutil.ReadAll(file.Body)
	//data := alldata[aes.BlockSize:]
	encodeiv := *file.Metadata["X-Amz-Iv"]
	s3encodekey := *file.Metadata["X-Amz-Key"]
	iv,_ := base64.StdEncoding.DecodeString(encodeiv)
	s3key,_ := base64.StdEncoding.DecodeString(s3encodekey)
	if (len(data) % encryption.BlockSize) != 0 {
	                 fmt.Println("There is a size issue!")
	       }
  return data, iv, s3key
}


func main() {
	bucket,localfilename,remfilename,context := "","","",""
	if len(os.Args) < 4 {
		fmt.Println("Usage: s3decrypt {localfilename} {remotefilename} {bucket} {context}\nError: Missing parameters")
		os.Exit(1)
	} else {
		localfilename = os.Args[1]
		remfilename = os.Args[2]
		bucket = os.Args[3]
		context = os.Args[4]
	}
	key := fetchkey(remfilename + ".key", bucket, context)
	file,iv,s3key := fetchfile(remfilename, bucket)
	s3finalkey := encryption.ECB_decrypt(s3key,key)
	result := encryption.Decryptfile(file,iv,s3finalkey)
	err := ioutil.WriteFile(localfilename, result, 0644)
	if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
}
