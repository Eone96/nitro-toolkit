package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"bytes"
	nitroToolkit "github.com/anyswap/nitro-toolkit"
	"github.com/mdlayher/vsock"
	"net"
	"github.com/anyswap/nitro-toolkit/test/common"
	"strconv"
)

var (
	port uint32 = 8888

	errorPrefix string = "Error in func FUNC_NAME: "

	vsockListener *vsock.Listener

	dataKey []byte = []byte("")
)

func initDependencies() error {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "initDependencies", 1)

	// vsock listener
	listener, err := vsock.Listen(port, nil)
	if err != nil {
		return errors.New(errPrefix + err.Error())
	}

	vsockListener = listener

	fmt.Println("success to start enclaveServer")
	return nil
}

func main() {
	defer func() {
		if vsockListener != nil {
			vsockListener.Close()
		}
	}()

	err := initDependencies()
	if err != nil {
		fmt.Println("failed to initDependencies, ", err.Error())
		return
	}

	// listen different connection
	for {
		conn, err := vsockListener.Accept()
		if err != nil {
			fmt.Println("vscokLister failed to accept new connection, ", err.Error())
		} else {
			payloadBytes := make([]byte, 1024*1024) // 1MB
			payloadLength, err := conn.Read(payloadBytes)
			if err != nil {
				fmt.Println("failed to read payload from vsock, ", err.Error())
			}
			var curPayload common.Payload
			json.Unmarshal(payloadBytes[:payloadLength], &curPayload)

			fmt.Println("received payload: " + strconv.FormatInt(int64(curPayload.ID), 10) + ":" + curPayload.Cmd)
			go handlePayload(conn, &curPayload)
		}
	}
}

func handlePayload(conn net.Conn, payload *common.Payload) {
	defer conn.Close()

	var response *common.Response

	switch payload.Cmd {

		case "generateDataKey":
			if len(dataKey) != 0 {
				response = &common.Response{
					ErrMsg: "there exist one available dataKey, pls do not generate repeatedly.",
					Data: []byte(""),
				}
			}else{
				curDataKey, encryptedDataKeyStr, err := nitroToolkit.GenerateDataKey(payload.IAMToken, payload.KmsConfig)

				if err != nil {
					response = &common.Response{
						ErrMsg: err.Error(),
						Data: []byte(""),
					}
				}else {
					dataKey = curDataKey
					response = &common.Response{
						ErrMsg: "",
						Data: []byte(encryptedDataKeyStr),
					}
				}
			}

		case "verifyEncryptedDataKey":
			curDataKey, err := nitroToolkit.DecryptDataKey(payload.IAMToken, payload.KmsConfig, string(payload.Data))

			if err != nil {
				response = &common.Response{
					ErrMsg: err.Error(),
					Data: []byte(""),
				}
			}else if !bytes.Equal(curDataKey, dataKey) {
				response = &common.Response{
					ErrMsg: "the input encryptedDataKey in not in use",
					Data: []byte(""),
				}
			}else {
				response = &common.Response{
					ErrMsg: "",
					Data: []byte("true"),
				}
			}

		case "encryptData":
			if len(dataKey) == 0 {
				response = &common.Response{
					ErrMsg: "no available dataKey, pls call generateDataKey to generate first",
					Data: []byte(""),
				}
			}else{
				cipherText, err := nitroToolkit.EncryptByDataKey(dataKey, payload.Data)
				if err != nil {
					response = &common.Response{
						ErrMsg: err.Error(),
						Data: []byte(""),
					}
				}else {
					response = &common.Response{
						ErrMsg: "",
						Data: cipherText,
					}
				}
			}

		case "decryptCipher":
			if len(dataKey) == 0 {
				response = &common.Response{
					ErrMsg: "no available dataKey, pls call generateDataKey to generate first",
					Data: []byte(""),
				}
			}else{
				plainText, err := nitroToolkit.DecryptByDataKey(dataKey, payload.Data)
				if err != nil {
					response = &common.Response{
						ErrMsg: err.Error(),
						Data: []byte(""),
					}
				}else {
					response = &common.Response{
						ErrMsg: "",
						Data: plainText,
					}
				}
			}

		case "getAttestation":
			attestation, err := nitroToolkit.GetAttestation(payload.Data, nil, nil)
			if err != nil {
				response = &common.Response{
					ErrMsg: err.Error(),
					Data: []byte(""),
				}
			}else {
				response = &common.Response{
					ErrMsg: "",
					Data: attestation,
				}
			}

		default:
			response = &common.Response{
				ErrMsg: "there is no matching payload for: " + payload.Cmd,
				Data: []byte(""),
			}
	}

	responseBytes, _ := json.Marshal(response)
	if _, err := conn.Write(responseBytes); err != nil {
		fmt.Println(strconv.FormatInt(int64(payload.ID), 10) + " " + payload.Cmd + ": failed to send response to vsock, " + err.Error())
	}
	fmt.Println(strconv.FormatInt(int64(payload.ID), 10) + " " + payload.Cmd + ": finished payload")
}
