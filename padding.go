// Package padding performs pkcs#7 padding and unpadding
package main

import (
	"crypto/aes"
	"errors"
)

//Unpad This function unpads pkcs#7 padding
func unpad(in []byte) []byte {
	if len(in) == 0 {
		genError(errors.New("Unpad - No data sent to unpad"))
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		genError(errors.New("Unpad - Padding larger than BlockSize or data"))
	} else if padding == 0 {
		genError(errors.New("Unpad - Does not contain proper padding"))
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			genError(errors.New("Unpad - Padded value larger than padding"))
		}
	}
	return in[:len(in)-int(padding)]
}

//Pad This function does pkcs#7 padding
func pad(in []byte) []byte {
	padding := aes.BlockSize - (len(in) % aes.BlockSize)
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}
