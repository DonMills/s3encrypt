package errorhandle

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"os"
)

//AWSErrorHandle takes an AWS generated error and handles it
func AWSErrorHandle(err error) {
	if awsErr, ok := err.(awserr.Error); ok {
		// Generic AWS error with Code, Message, and original error (if any)
		if origErr := awsErr.OrigErr(); origErr != nil {
			fmt.Printf("AWS Error: %s - %s %v\n", awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
			os.Exit(1)
		} else {
			fmt.Printf("AWS Error: %s - %s \n", awsErr.Code(), awsErr.Message())
		}
		os.Exit(1)
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
	return
}
