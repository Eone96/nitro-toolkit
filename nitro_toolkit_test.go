package nitro_toolkit

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"
	"github.com/hf/nitrite"
)

// only success in aws ec2 with iamrole config
func TestGetIAMToken(t *testing.T) {
	token, err := GetIAMToken()
	if err != nil {
		t.Errorf("GetIAMToken() failed with error: %v", err)
		return
	}
	if token.AccessKeyId == "" || token.SecretAccessKey == "" || token.Token == "" {
		t.Error("GetIAMToken() returned an empty token")
		return
	}
}

// only success in aws ec2 with iamrole config
func TestGenerateDataKeyAndDecryptDataKey(t *testing.T) {
	iamToken, err := GetIAMToken()
	if err != nil {
		t.Errorf("GetIAMToken() failed with error: %v", err)
		return
	}
	kmsConfig := &KmsConfig{
		AWSEnclaveKmsCliPath: "aws_enclave_kms_cli_path",
		Region:               "ap-southeast-1",
		ProxyPort:            "8000",
		KeyId:                "4df5234b-8111-4409-9fb3-1d16bb9f5bd1",
		DataKeyType:          "AES-256",
	}
	dataKey, encryptedDataKeyStr, err := GenerateDataKey(iamToken, kmsConfig)
	if err != nil {
		t.Errorf("Error in GenerateDataKey: %v", err)
	}
	decryptedDataKey, err := DecryptDataKey(iamToken, kmsConfig, encryptedDataKeyStr)
	if err != nil {
		t.Errorf("Error in DecryptDataKey: %v", err)
	}
	if !bytes.Equal(dataKey, decryptedDataKey) {
		t.Errorf("Error in DecryptDataKey: decryptedDataKey does not match generated dataKey")
	}
}

func TestEncryptByDataKeyAndDecryptByDataKey(t *testing.T) {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Errorf("failed to generate data key: %v", err)
		return
	}
	data := []byte("hello world")

	cipherText, err := EncryptByDataKey(dataKey, data)
	if err != nil {
		t.Errorf("EncryptByDataKey() failed with error: %v", err)
		return
	}

	decryptedData, err := DecryptByDataKey(dataKey, cipherText)
	if err != nil {
		t.Errorf("DecryptByDataKey() failed with error: %v", err)
		return
	}

	if !bytes.Equal(data, decryptedData) {
		t.Error("EncryptByDataKey() and DecryptByDataKey() returned different data")
		return
	}
}

// only success in aws ec2 enclave
func TestGetAttestation(t *testing.T) {
	userNonce := []byte("user nonce")
	userData := []byte("user data")
	userPk := []byte("user pk")
	
	attestation, err := GetAttestation(userNonce, userData, userPk)
	if err != nil {
		t.Fatalf("Failed to get attestation: %v", err)
	}

	if _, err := GetReadbleAttestationDocu(attestation); err != nil {
		t.Fatalf("Failed to parse attestation: %v", err)
	}
}

func TestGetReadbleAttestationDocu(t *testing.T) {
	attestationFile := "../testdata/attestation.txt"
	attestationBytes, err := ioutil.ReadFile(attestationFile)
	if err != nil {
		t.Fatalf("Failed to read attestation file: %v", err)
	}
	attestationBytes, err = base64.StdEncoding.DecodeString(string(attestationBytes))
	if err != nil {
		t.Fatalf("Failed to decode base64 attestation file: %v", err)
	}

	doc, err := GetReadbleAttestationDocu(attestationBytes)
	if err != nil {
		t.Fatalf("Failed to parse attestation: %v", err)
	}

	if doc.ModuleID != "i-080ef084ebaa566bd-enc018804ce6f6420c9" {
		t.Errorf("Unexpected module id: %s", doc.ModuleID)
	}
	if doc.Timestamp != uint64(1683707825132) {
		t.Errorf("Unexpected timestamp: %v", doc.Timestamp)
	}
	if doc.Digest != "SHA384" {
		t.Errorf("Unexpected digest: %s", doc.Digest)
	}
	expectedPCR3 := "\rbI\xfciҗ\xcb\xd2\xf1Y\xec\x93\xe7|˂l\x80\xf7\x8a\x02c\x81\xfb\xc1rǏ\xb1\x18'\x99\xe4\xd20\x15\xe2\xb3&\xf5\xa8.ϟ\x8apq"
	if !bytes.Equal(doc.PCRs[3], []byte(expectedPCR3)) {
		t.Errorf("Unexpected PCR3: %v", doc.PCRs)
	}
	if !bytes.Equal(doc.UserData, []byte("key-creater")) {
		t.Errorf("Unexpected user data: %v", doc.UserData)
	}
	if !bytes.Equal(doc.Nonce, []byte("10086")) {
		t.Errorf("Unexpected nonce: %v", doc.Nonce)
	}
}

func TestVerifyExternalAttestation(t *testing.T) {
	// base64 Encode String
	attestationFile := "../testdata/attestation.txt"
	attestationBytes, err := ioutil.ReadFile(attestationFile)
	if err != nil {
		t.Fatalf("Failed to read attestation file: %v", err)
	}
	attestationBytes, err = base64.StdEncoding.DecodeString(string(attestationBytes))
	if err != nil {
		t.Fatalf("Failed to decode base64 attestation file: %v", err)
	}

	rootCAs := x509.NewCertPool()
	rootCAFile := "../testdata/root_ca.pem"
	rootCABytes, err := ioutil.ReadFile(rootCAFile)
	if err != nil {
		t.Fatalf("Failed to read root CA file: %v", err)
	}
	if !rootCAs.AppendCertsFromPEM(rootCABytes) {
		t.Fatalf("Failed to parse root CA: %v", err)
	}
	if _, err := VerifyAttestation(attestationBytes, rootCAs, nil); err != nil {
		// by design, as the attestation file is expired
		if !strings.Contains(err.Error(), "certificate has expired") {
			t.Fatalf("Failed to verify attestation: %v", err)
		}
	}
}

// only success in aws ec2 enclave
func TestVerifyAttestation(t *testing.T) {
	userNonce := []byte("user nonce")
	userData := []byte("user data")
	userPk := []byte("user pk")
	
	attestation, err := GetAttestation(userNonce, userData, userPk)
	if err != nil {
		t.Fatalf("Failed to get attestation: %v", err)
	}

	callback := func(d *nitrite.Document) bool {
		if !bytes.Equal(d.Nonce, userNonce) {
			t.Errorf("Unexpected nonce: %v", d.Nonce)
			return false
		}
		if !bytes.Equal(d.UserData, userData) {
			t.Errorf("Unexpected user data: %v", d.UserData)
			return false
		}
		if !bytes.Equal(d.PublicKey, userPk) {
			t.Errorf("Unexpected public key: %v", d.PublicKey)
			return false
		}
		// pcrs check
		return true
	}

	rootCAs := x509.NewCertPool()
	rootCAFile := "../testdata/root_ca.pem"
	rootCABytes, err := ioutil.ReadFile(rootCAFile)
	if err != nil {
		t.Fatalf("Failed to read root CA file: %v", err)
	}
	if !rootCAs.AppendCertsFromPEM(rootCABytes) {
		t.Fatalf("Failed to parse root CA: %v", err)
	}
	if _, err := VerifyAttestation(attestation, rootCAs, callback); err != nil {
		t.Fatalf("Failed to verify attestation: %v", err)
	}
}