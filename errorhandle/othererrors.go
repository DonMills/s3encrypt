package errorhandle

import (
	"fmt"
	"os"
)

//GenError takes other generated errors and handles them
func GenError(err error) {
	fmt.Printf("Error: %s", err.Error())
	os.Exit(1)
	return
}
