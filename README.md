# go-kms-s3
A tool designed to work with the [ruby-kms-s3-gem](https://github.com/DonMills/ruby-kms-s3-gem).  
Currently can download files from S3 that are encrypted and uploaded with the gem.
___
How this works is that it takes a file that you have uploaded via the ruby gem, fetches the key, decrypts the key with the appropriate EncryptionContext via KMS, then takes that key and unencrypts the key stored with the file, and then uses _that_ key to decrypt the file and save it in the location specified.
___
## How to build:
This tool requires the "aws-sdk-go" be installed.
```
go get github.com/aws/aws-sdk-go/
```
after this, you can build the tool.
```bash
go build s3decrypt.go
./s3decrypt 
Usage: s3decrypt {localfilename} {remotefilename} {bucket} {context}
```


Alternatively, if you have [glide](https://github.com/Masterminds/glide) installed, you can just clone the repo and build like so:
```
glide up
go build s3decrypt.go
```
