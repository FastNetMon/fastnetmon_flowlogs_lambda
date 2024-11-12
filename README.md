# Introduction

Amazon AWS Lambda function to transform AWS VPC Flow Logs into format suitable for FastNetMon.

As an additional feature we have logic to replace internal IPs by external globally routable IPs with caching logic. 

You can find detailed guide here: https://fastnetmon.com/docs-fnm-advanced/fastnetmon-and-amazon-vpc-flow-logs/

# Build process

```
GOOS=linux GOARCH=amd64 go build -o bootstrap main.go
zip lambda-handler.zip bootstrap
```

# Cap'n'Proto schema rebuild

```
go get -u -t zombiezen.com/go/capnproto2/...
PATH=$PATH:/home/username/go/bin capnp compile -I/home/username/go/src/zombiezen.com/go/capnproto2/std -ogo fastntemon/simple_packet.capnp
```
