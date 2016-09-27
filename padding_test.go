package main

import (
	"fmt"
	"testing"
)

func TestPadUnpad(t *testing.T) {
	testdata := []byte("This is the test data")
	fmt.Printf("Test Data: %v\n", testdata)
	paddata := pad(testdata)
	fmt.Printf("Padded Data: %v\n", paddata)
	unpaddata := unpad(paddata)
	fmt.Printf("Unpadded Data: %v\n", unpaddata)
	if string(testdata) != string(unpaddata) {
		t.Error("Padding/Unpadding failed! Error in Pad/Unpad functions")
	}
}
