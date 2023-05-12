package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	nitroToolkit "github.com/anyswap/nitro-toolkit"
	"github.com/mdlayher/vsock"
	"encoding/base64"
	"strconv"
	"github.com/anyswap/nitro-toolkit/test/common"
	"os"
	"time"
)

var (
	cid  uint32 = 16
	port uint32 = 8888

	msgPrefix string = "RequestID REQUEST_ID, func FUNC_NAME: "

	kmsConfig *nitroToolkit.KmsConfig
	iamToken  *nitroToolkit.IAMToken
)

func initDependencies() error {
	// kmsConfig
	kmsConfig = &nitroToolkit.KmsConfig{
		AWSEnclaveKmsCliPath: "/app/kmstool_enclave_cli", //
		Region:               "ap-southeast-1",
		ProxyPort:            "8000",
		KeyId:                "4df5234b-8111-4409-9fb3-1d16bb9f5bd1",
		DataKeyType:          "AES-256",
	}
	return nil
}

func sendPayloadAndGetResponse(payload *common.Payload) (*common.Response, error) {
	curMsgPrefix := strings.Replace(msgPrefix, "FUNC_NAME", "sendPayloadAndGetResponse", 1)
	curMsgPrefix = strings.Replace(curMsgPrefix, "REQUEST_ID", strconv.FormatInt(int64(payload.ID), 10), 1)

	conn, err := vsock.Dial(cid, port, nil)
	if err != nil {
		curErr := errors.New(curMsgPrefix + "failed to dial enclaveSer: " + payload.Cmd + ", " + err.Error())
		fmt.Println(curErr.Error())
		return nil, curErr
	}
	defer conn.Close()

	payloadBytes , _ := json.Marshal(payload)
	if _, err := conn.Write(payloadBytes); err != nil {
		curErr := errors.New(curMsgPrefix + "failed to send payload: " + payload.Cmd + ", " + err.Error())
		fmt.Println(curErr.Error())
		return nil, curErr
	}
	fmt.Println(curMsgPrefix + "success to send payload: " + payload.Cmd)

	var response common.Response
	responseBytes := make([]byte, 1024 * 1024) // 1MB
	responseLength, err := conn.Read(responseBytes)
	if err != nil {
		curErr := errors.New(curMsgPrefix + "failed to received payload response: " + payload.Cmd + ", " + err.Error())
		fmt.Println(curErr.Error())
		return nil, curErr
	}
	fmt.Println(curMsgPrefix + "success to received payload response: " + payload.Cmd)

	json.Unmarshal(responseBytes[:responseLength], &response)
	return &response, nil
}

func main() {
	err := initDependencies()
	if err != nil {
		fmt.Println("failed to initDependencies, ", err.Error())
		return
	}

	concurrentSizeInt64, err := strconv.ParseInt(os.Getenv("CONCURRENT_SIZE"), 10, 32)
	if err != nil || concurrentSizeInt64 == 0 {
		concurrentSizeInt64 = 1
	}
	fmt.Println("enviroment CONCURRENT_SIZE: " + strconv.FormatInt(concurrentSizeInt64, 10))
	concurrentSize := int(concurrentSizeInt64)

	loopTimes := 0
	for {
		for i := 0; i < concurrentSize; i++ {
			go oneTimeCall(loopTimes * concurrentSize + i)
		}

		loopTimes++
		if concurrentSize == 1 {
			break
		}
		time.Sleep(2 * time.Second)
	}
}

func oneTimeCall(requestId int) {
	curMsgPrefix := strings.Replace(msgPrefix, "REQUEST_ID", strconv.FormatInt(int64(requestId), 10), 1)

	var curPayload *common.Payload
	var curResponse *common.Response

	// 0. iamToken
	iamToken, _ := nitroToolkit.GetIAMToken()

	// 1. get encryptedDataKeyStr
	temMsgPrefix := strings.Replace(curMsgPrefix, "FUNC_NAME", "generateDataKey", 1)
	encryptedDataKeyStr := ""

	curPayload = &common.Payload{
		ID: requestId,
		Cmd: "generateDataKey",
		IAMToken: iamToken,
		KmsConfig: kmsConfig,
		Data: []byte(""),
	}
	curResponse, _ = sendPayloadAndGetResponse(curPayload)
	if curResponse.ErrMsg != "" {
		fmt.Println(temMsgPrefix + "error msg: " + curResponse.ErrMsg)
	}else {
		encryptedDataKeyStr = string(curResponse.Data)
		fmt.Println(temMsgPrefix + "obtained encryptedDataKeyStr: " + encryptedDataKeyStr)
	}

	// 2. verify encryptedDataKeyStr
	temMsgPrefix = strings.Replace(curMsgPrefix, "FUNC_NAME", "verifyEncryptedDataKey", 1)
	dataKeyVerificationRlt := "false"

	curPayload = &common.Payload{
		ID: requestId,
		Cmd: "verifyEncryptedDataKey",
		IAMToken: iamToken,
		KmsConfig: kmsConfig,
		Data: []byte(encryptedDataKeyStr),
	}
	curResponse, _ = sendPayloadAndGetResponse(curPayload)
	if curResponse.ErrMsg != "" {
		fmt.Println(temMsgPrefix + "error msg: " + curResponse.ErrMsg)
	}else {
		dataKeyVerificationRlt = string(curResponse.Data)
		fmt.Println(temMsgPrefix + "verify encryptedDataKeyStr result: " + dataKeyVerificationRlt)
	}

	// 3. use dataKey to encrypt data
	temMsgPrefix = strings.Replace(curMsgPrefix, "FUNC_NAME", "encryptData", 1)
	plainText := []byte("hello, nitro enclave")
	var cipherText []byte

	curPayload = &common.Payload{
		ID: requestId,
		Cmd: "encryptData",
		IAMToken: iamToken,
		KmsConfig: kmsConfig,
		Data: plainText,
	}
	curResponse, _ = sendPayloadAndGetResponse(curPayload)
	if curResponse.ErrMsg != "" {
		fmt.Println(temMsgPrefix + "error msg: "  + curResponse.ErrMsg)
	}else {
		cipherText = curResponse.Data
		fmt.Println(temMsgPrefix + "encrypt plainText by dataKey: " + string(cipherText))
	}

	// 4. use dataKey to decrypt ciphertext
	temMsgPrefix = strings.Replace(curMsgPrefix, "FUNC_NAME", "decryptCipher", 1)
	var outputPlainText []byte

	curPayload = &common.Payload{
		ID: requestId,
		Cmd: "decryptCipher",
		IAMToken: iamToken,
		KmsConfig: kmsConfig,
		Data: cipherText,
	}
	curResponse, _ = sendPayloadAndGetResponse(curPayload)
	if curResponse.ErrMsg != "" {
		fmt.Println(temMsgPrefix + "error msg: "  + curResponse.ErrMsg)
	}else {
		outputPlainText = curResponse.Data
		fmt.Println(temMsgPrefix + "decrypt cipherText by dataKey: " + string(outputPlainText))
	}

	// 5. get attestation
	temMsgPrefix = strings.Replace(curMsgPrefix, "FUNC_NAME", "getAttestation", 1)
	var attestation []byte

	curPayload = &common.Payload{
		ID: requestId,
		Cmd: "getAttestation",
		IAMToken: iamToken,
		KmsConfig: kmsConfig,
		Data: []byte("user data"),
	}
	curResponse, _ = sendPayloadAndGetResponse(curPayload)
	if curResponse.ErrMsg != "" {
		fmt.Println(temMsgPrefix + "error msg: "  + curResponse.ErrMsg)
	}else {
		attestation = curResponse.Data
		fmt.Println(temMsgPrefix + "obtained attestation (base64 encoded): " + base64.StdEncoding.EncodeToString(attestation))
	}

	// 6. get readable document
	temMsgPrefix = strings.Replace(curMsgPrefix, "FUNC_NAME", "getReadableDocument", 1)
	var documentJsonBytes []byte

	document, err := nitroToolkit.GetReadbleAttestationDocu(attestation)
	if err != nil {
		fmt.Println(temMsgPrefix + "failed to parse readable documnet, ", err.Error())
	}
	documentJsonBytes, _ = json.Marshal(document)
	fmt.Println(temMsgPrefix + "obtained readable document: " + string(documentJsonBytes))
	
	// 7. verify attestation 
	temMsgPrefix = strings.Replace(curMsgPrefix, "FUNC_NAME", "verifyAttestation", 1)

	attestationVerificationRlt, err := nitroToolkit.VerifyAttestation(attestation, nil, nil)
	if err != nil {
		fmt.Println(temMsgPrefix + "failed to verify attestation, ", err.Error())
	}
	fmt.Println(temMsgPrefix + "verify attestation result: " + strconv.FormatBool(attestationVerificationRlt))
}
