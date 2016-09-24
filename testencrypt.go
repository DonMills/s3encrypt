package main

import (
	"./encryption"
	"rand"
)

func main() {
	data := []byte("Test String one")
	key := make([]byte, 16)
	_, err := rand.Read(key)
	ctext, iv := encryption.EncryptFile(data, key)

}
