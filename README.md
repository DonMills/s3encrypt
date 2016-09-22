# go-kms-s3
A tool designed to work with the [ruby-kms-s3-gem](https://github.com/DonMills/ruby-kms-s3-gem).  
Currently can download files from S3 that are encrypted and uploaded with the gem.
```bash
go build s3decrypt.go
./s3decrypt 
Usage: s3decrypt {localfilename} {remotefilename} {bucket} {context}
```
