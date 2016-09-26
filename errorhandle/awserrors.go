package errorhandle

import (
	"error"
	"fmt"
)

//AWSErrorHandle takes an AWS generated error and handles it
func AWSErrorHandle(err Error) {
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
	return
}
