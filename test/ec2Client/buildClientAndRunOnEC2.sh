#!/bin/bash

CUR_PATH=$(dirname $0)
echo "current working path: $CUR_PATH"
cd $CUR_PATH

go build ec2Client.go

chmod +x ec2Client
./ec2Client