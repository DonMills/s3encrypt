package awsfuncs

import (
	"testing"
)

func TestKMSGenerateDecrypt(t *testing.T) {
	GenerateKey("", "testkey")
}
