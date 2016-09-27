package padding

import (
	"fmt"
	"testing"
)

func TestPadUnpad(t *testing.T) {
	testdata := []byte("This is the test data")
	fmt.Printf("Test Data: %v\n", testdata)
	paddata := Pad(testdata)
	fmt.Printf("Padded Data: %v\n", paddata)
	unpaddata := Unpad(paddata)
	fmt.Printf("Unpadded Data: %v\n", unpaddata)
	if string(testdata) != string(unpaddata) {
		t.Error("Padding/Unpadding failed! Error in Pad/Unpad functions")
	}
}
