package padding

import (
	"crypto/aes"
)
//Unpad This function unpads pkcs#7 padding
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}
//Pad This function does pkcs#7 padding
func Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}
