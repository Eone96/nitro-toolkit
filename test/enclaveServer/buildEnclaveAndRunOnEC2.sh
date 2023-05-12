#!/bin/bash

CUR_PATH=$(dirname $0)
echo "current working path: $CUR_PATH"
cd $CUR_PATH

FILE=enclave_server.eif
ENCLAVE_CPU_COUNT=2
ENCLAVE_MEMORY_SIZE=1024
ENCLAVE_CLIENT_CID=16
REGION=ap-southeast-1

if [ -f "$FILE" ]; then
    rm $FILE
fi

RunningEnclave=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
if [ -n "$RunningEnclave" ]; then
	nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID");
fi

go build enclaveServer.go

docker build -t enclave_server:latest .
docker image ls

nitro-cli build-enclave --docker-uri enclave_server:latest  --output-file $FILE

# kms proxy
vsock-proxy 8000 kms.$REGION.amazonaws.com 443 &

nitro-cli run-enclave --cpu-count $ENCLAVE_CPU_COUNT --memory $ENCLAVE_MEMORY_SIZE --enclave-cid $ENCLAVE_CLIENT_CID --eif-path $FILE
