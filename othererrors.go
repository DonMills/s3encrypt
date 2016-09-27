package main

import (
	"fmt"
	"os"
)

//ErrorHandle takes other generated errors and handles them
func genError(err error) {
	fmt.Printf("Error: %s", err.Error())
	os.Exit(1)
	return
}
