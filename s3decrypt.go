package main

import (
	"DonMills/go-kms-s3/awsfuncs"
	"DonMills/go-kms-s3/encryption"
	"fmt"
	"github.com/urfave/cli"
	"io/ioutil"
	"os"
	"time"
)

func decrypt(localfilename string, remfilename string, bucket string, context string) {
	key := awsfuncs.FetchKey(remfilename+".key", bucket, context)
	file, iv, s3key := awsfuncs.FetchFile(remfilename, bucket)
	s3finalkey := encryption.ECBDecrypt(s3key, key)
	result := encryption.DecryptFile(file, iv, s3finalkey)
	err := ioutil.WriteFile(localfilename, result, 0644)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func main() {
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
	}
	app.Run(os.Args)
}
