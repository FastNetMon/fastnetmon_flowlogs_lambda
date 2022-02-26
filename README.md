# Introduction

Amazon AWS Lambda function to transform AWS VPC Flow Logs into format suitable for FastNetMon

You can find details guide here: https://fastnetmon.com/docs-fnm-advanced/fastnetmon-and-amazon-vpc-flow-logs/

# Build process

```
go build
cp bin/fastnetmon_flowlogs_lambda fastnetmon_flowlogs_lambda
zip fastnetmon_flowlogs_lambda.zip fastnetmon_flowlogs_lambda
```

# Cap'n'Proto schema rebuild

```
go get -u -t zombiezen.com/go/capnproto2/...
PATH=$PATH:/home/username/go/bin capnp compile -I/home/username/go/src/zombiezen.com/go/capnproto2/std -ogo fastntemon/simple_packet.capnp
```
