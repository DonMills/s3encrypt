package main

import (
	"DonMills/go-kms-s3/awsfuncs"
	"DonMills/go-kms-s3/encryption"
	"DonMills/go-kms-s3/errorhandle"

	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/urfave/cli"
)

func decrypt(localfilename string, remfilename string, bucket string, context string) {
	key := awsfuncs.FetchKey(remfilename+".key", bucket, context)
	file, iv, s3key := awsfuncs.FetchFile(remfilename, bucket)
	s3finalkey := encryption.ECBDecrypt(s3key, key)
	result := encryption.DecryptFile(file, iv, s3finalkey)
	err := ioutil.WriteFile(localfilename, result, 0644)
	if err != nil {
		errorhandle.GenError(err)
	}
}

func encrypt(localfilename string, remfilename string, bucket string, context string, sse string, cmkID string) {
	filedata, err := ioutil.ReadFile(localfilename)
	if err != nil {
		errorhandle.GenError(err)
	}
	cipherenvkey, plainenvkey := awsfuncs.GenerateEnvKey(cmkID, context)
	awsfuncs.PutEncKey(cipherenvkey, remfilename, bucket, sse)
	datakey := encryption.GenerateDataKey()
	ciphertext, iv := encryption.EncryptFile(filedata, datakey)
	cryptdatakey := encryption.ECBEncrypt(datakey, plainenvkey)
	awsfuncs.PutEncFile(ciphertext, remfilename, bucket, iv, cryptdatakey, sse)
}

func main() {
	var sse string
	var cmkID string

	app := cli.NewApp()
	app.Name = "s3encrypt"
	app.Usage = "Send and receive encrypted files in S3"
	app.HelpName = "s3encrypt"
	app.UsageText = "s3encrypt [command] {command specific options}"
	app.ArgsUsage = "s3encrypt [command]"
	app.Version = "0.8"
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Don Mills",
			Email: "don.mills@gmail.com",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "decrypt",
			Aliases:   []string{"d"},
			Usage:     "Fetch and decrypt a file from S3",
			ArgsUsage: "[localfilename] [remotefilename] [bucket] [context]",
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 4 {
					fmt.Println("Usage: s3decrypt decrypt [localfilename] [remotefilename] [bucket] [context]")
					os.Exit(1)
				} else {
					decrypt(c.Args().Get(0), c.Args().Get(1), c.Args().Get(2), c.Args().Get(3))
				}
				return nil
			},
		},
		{
			Name:      "encrypt",
			Aliases:   []string{"e"},
			Usage:     "Fetch and decrypt a file from S3",
			ArgsUsage: "[localfilename] [remotefilename] [bucket] [context]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "c",
					Usage:       "The customer master key id - can set with S3ENCRYPT_CMKID environment variable",
					EnvVar:      "S3ENCRYPT_CMKID",
					Destination: &cmkID,
				},
				cli.StringFlag{
					Name:        "s",
					Usage:       "The ServerSideEncryption method to use - default is none, valid options are \"AES256\" or \"aws:kms\"",
					Value:       "nil",
					Destination: &sse,
				},
			},
			Action: func(c *cli.Context) error {
				if len(c.Args()) < 4 {
					fmt.Println("Usage: s3decrypt encrypt [localfilename] [remotefilename] [bucket] [context] -c [customermasterkey] -s [AES256|aws:kms]")
					os.Exit(1)
				} else {
					encrypt(c.Args().Get(0), c.Args().Get(1), c.Args().Get(2), c.Args().Get(3), sse, cmkID)
				}
				return nil
			},
		},
	}
	app.Run(os.Args)
}
