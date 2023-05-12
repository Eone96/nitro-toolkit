package nitro_toolkit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nitrite"
)

type IAMToken struct {
	Code                string
	LastUpdated         string
	Type                string
	AccessKeyId         string
	SecretAccessKey     string
	Token               string
	Expiration          string // "2023-05-10T20:04:26Z", Z zero timestone
	ExpirationTimestamp int64
}

type KmsConfig struct {
	AWSEnclaveKmsCliPath string
	Region               string
	ProxyPort            string
	KeyId                string
	DataKeyType          string
}

type cosePayload struct {
	_ struct{} `cbor:",toarray"`

	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// used by both en2 instance and enclave, not wrapped by class

var (
	curIAMToken *IAMToken
	errorPrefix string = "Error in func FUNC_NAME: "
)

func GetIAMToken() (*IAMToken, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "GetIAMToken", 1)

	curTimestamp := time.Now().Unix()
	if curIAMToken != nil && curIAMToken.ExpirationTimestamp > (curTimestamp+5) {
		return curIAMToken, nil
	}

	var iamToken IAMToken

	res, err := http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return nil, errors.New(errPrefix + err.Error())
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	iamRoleName := string(body)

	profileUri := fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", iamRoleName)
	res, err = http.Get(profileUri)
	if err != nil {
		return nil, errors.New(errPrefix + err.Error())
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if err := json.Unmarshal(body, &iamToken); err != nil {
		return nil, errors.New(errPrefix + "the return iamToken with wrong format")
	}

	timeFormat := "2006-01-02 15:04:05"
	cleanTimeStr := strings.Replace(strings.Replace(iamToken.Expiration, "T", " ", 1), "Z", "", 1)
	timepoint, err := time.Parse(timeFormat, cleanTimeStr)
	if err != nil {
		return nil, errors.New(errPrefix + err.Error())
	}
	iamToken.ExpirationTimestamp = timepoint.Unix()

	curIAMToken = &iamToken

	return curIAMToken, nil
}

func GenerateDataKey(iamToken *IAMToken, kmsConfig *KmsConfig) ([]byte, string, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "GenerateDataKey", 1)

	if iamToken == nil || kmsConfig == nil {
		return nil, "", errors.New(errPrefix + "iamToken or kmsConfig is nil")
	}

	if _, err := os.Stat(kmsConfig.AWSEnclaveKmsCliPath); os.IsNotExist(err) {
		return nil, "", errors.New(errPrefix + "aws enclave kms client not exist, " + err.Error())
	}

	cmd := exec.Command(
		kmsConfig.AWSEnclaveKmsCliPath,
		"genkey",
		"--region", kmsConfig.Region,
		"--proxy-port", kmsConfig.ProxyPort,
		"--key-id", kmsConfig.KeyId,
		"--key-spec", kmsConfig.DataKeyType,
		"--aws-access-key-id", iamToken.AccessKeyId,
		"--aws-secret-access-key", iamToken.SecretAccessKey,
		"--aws-session-token", iamToken.Token)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, "", errors.New(errPrefix + "failed to exec genkey commands, " + err.Error())
	}

	rltStrs := strings.Split(out.String(), "\n")
	if len(rltStrs) < 2 || !strings.Contains(rltStrs[0], ":") || !strings.Contains(rltStrs[1], ":") {
		return nil, "", errors.New(errPrefix + "the return datakey with wrong format, " + out.String())
	}
	encryptedDataKeyStr := strings.TrimSpace(strings.Split(rltStrs[0], ":")[1])
	dataKeyStr := strings.TrimSpace(strings.Split(rltStrs[1], ":")[1])
	dataKey, err := base64.StdEncoding.DecodeString(dataKeyStr)
	if err != nil {
		return nil, "", errors.New(errPrefix + "failed to decode base64 string, " + dataKeyStr)
	}

	return dataKey, encryptedDataKeyStr, nil
}

func DecryptDataKey(iamToken *IAMToken, kmsConfig *KmsConfig, encryptedDataKeyStr string) ([]byte, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "DecryptDataKey", 1)

	if iamToken == nil || kmsConfig == nil || encryptedDataKeyStr == "" {
		return nil, errors.New(errPrefix + "iamToken or kmsConfig is nil, or encryptedDataKeyStr is empty string")
	}

	if _, err := os.Stat(kmsConfig.AWSEnclaveKmsCliPath); os.IsNotExist(err) {
		return nil, errors.New(errPrefix + "aws enclave kms client not exist, " + err.Error())
	}

	cmd := exec.Command(
		kmsConfig.AWSEnclaveKmsCliPath,
		"decrypt",
		"--region", kmsConfig.Region,
		"--proxy-port", kmsConfig.ProxyPort,
		"--ciphertext", encryptedDataKeyStr,
		"--aws-access-key-id", iamToken.AccessKeyId,
		"--aws-secret-access-key", iamToken.SecretAccessKey,
		"--aws-session-token", iamToken.Token)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, errors.New(errPrefix + "failed to exec decrypt commands, " + err.Error())
	}

	rltStr := out.String()
	if !strings.Contains(rltStr, ":") {
		return nil, errors.New(errPrefix + "return datakey with wrong format, " + rltStr)
	}
	dataKeyStr := strings.TrimSpace(strings.Split(rltStr, ":")[1])
	dataKey, err := base64.StdEncoding.DecodeString(dataKeyStr)
	if err != nil {
		return nil, errors.New(errPrefix + "failed to decode base64 string, " + dataKeyStr)
	}

	return dataKey, nil
}

func EncryptByDataKey(dataKey, data []byte) ([]byte, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "EncryptByDataKey", 1)

	if dataKey == nil || data == nil || len(dataKey) == 0 || len(data) == 0 {
		return nil, errors.New(errPrefix + "dataKey or data is nil")
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, errors.New(errPrefix + "failed to initialize the AES encryption" + err.Error())
	}

	// iv + ciphertext
	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New(errPrefix + "failed to generate random bytes" + err.Error())
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return cipherText, nil
}

func DecryptByDataKey(dataKey, cipherText []byte) ([]byte, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "DecryptByDataKey", 1)

	if dataKey == nil || cipherText == nil || len(dataKey) == 0 || len(cipherText) == 0 {
		return nil, errors.New(errPrefix + "dataKey or cipherText is nil")
	}
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New(errPrefix + "cipherText is too short")
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, errors.New(errPrefix + "failed to initialize the AES encryption" + err.Error())
	}

	data := make([]byte, len(cipherText)-aes.BlockSize)

	// ciphertext = iv + cipher
	iv := cipherText[:aes.BlockSize]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, cipherText[aes.BlockSize:])

	return data, nil
}

// userNonce, userData 1-512, userPk, 1-1024 bytes
// return attestationDocument, base64 encoded, cbor cosePayload
func GetAttestation(userNonce, userData, userPk []byte) ([]byte, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "GetAttestation", 1)

	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, errors.New(errPrefix + "faild to open nsm session" + err.Error())
	}
	defer s.Close()

	res, err := s.Send(&request.Attestation{
		Nonce:     userNonce,
		UserData:  userData,
		PublicKey: userPk,
	})
	if err != nil {
		return nil, errors.New(errPrefix + "faild to send nsm request" + err.Error())
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New(errPrefix + "faild to obtain attestation" + err.Error())
	}

	return res.Attestation.Document, nil
}

func GetReadbleAttestationDocu(document []byte) (*nitrite.Document, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "GetReadbleAttestationDocu", 1)

	if len(document) == 0 {
		return nil, errors.New(errPrefix + "document is null")
	}

	cose := cosePayload{}
	doc := nitrite.Document{}

	if err := cbor.Unmarshal(document, &cose); err != nil {
		return nil, errors.New(errPrefix + "faild to cbor unmarshal cosPayload" + err.Error())
	}
	if err := cbor.Unmarshal(cose.Payload, &doc); err != nil {
		return nil, errors.New(errPrefix + "faild to cbor unmarshal Document" + err.Error())
	}

	return &doc, nil
}

// in callBack, user check: expectedUserNonce, expectedUserData, expectedUserPk, expectedPCRs
// certRoots and callBack can be nil
// 		aws nitro enclave cert roots: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
func VerifyAttestation(attestation []byte, certRoots *x509.CertPool, callBack func(*nitrite.Document) bool) (bool, error) {
	errPrefix := strings.Replace(errorPrefix, "FUNC_NAME", "GetReadbleAttestationDocu", 1)

	if attestation == nil {
		return false, errors.New(errPrefix + "attestation is nil")
	}

	res, err := nitrite.Verify(attestation, nitrite.VerifyOptions{Roots: certRoots})

	if err != nil {
		return false, errors.New(errPrefix + "failed to verify the attestation, " + err.Error())
	}
	if !res.SignatureOK {
		return false, errors.New(errPrefix + "wrong attestation signature")
	}
	if callBack != nil {
		if rlt := callBack(res.Document); !rlt {
			return false, errors.New(errPrefix + "failed to check user data or pcrs")
		}
	}

	return true, nil
}
