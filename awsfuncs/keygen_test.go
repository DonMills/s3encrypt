package awsfuncs

import (
	"testing"
)

func TestKMSGenerateDecrypt(t *testing.T) {
	GenerateEnvKey("", "testkey")
}
