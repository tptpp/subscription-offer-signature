package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	"math/big"
	"time"
)

var (
	// the id and private key below is got from here:
	// https://developer.apple.com/documentation/storekit/in-app_purchase/generating_a_subscription_offer_signature_using_node_js
	AppleKeyId      = "C76V8WWKQ2"
	ApplePrivateKey = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgYSpsqmmTv/zB/cW4
diRuTCtlhES7BijgfuSTSuUZr8ygCgYIKoZIzj0DAQehRANCAAT1KXkAZvSGvHfZ
rEHyDLDaf4m4b/HYyOOkNEZB0TcLezlCOeDny67Ab8aOxhdTNUOthHB3saF/oDQi
5eWFFfFc
-----END PRIVATE KEY-----`

	privateKey, _ = AuthKeyFromBytes([]byte(ApplePrivateKey))
	sep           = "\u2063"
)

func AuthKeyFromBytes(key []byte) (*ecdsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("token: AuthKey must be a valid .p8 PEM file")
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, errors.New("token: AuthKey must be of type ecdsa.privateKey")
	}

	return pkey, nil
}

type SignParams struct {
	AppBundleID         string `json:"appBundleID"`
	ProductIdentifier   string `json:"productIdentifier"`
	OfferID             string `json:"offerID"`
	ApplicationUsername string `json:"applicationUsername"`
}

type SignResult struct {
	KeyID     string `json:"keyID"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

func Sign(params *SignParams) (SignResult, error) {
	_nonce, _ := uuid.NewV4()
	nonce := _nonce.String()
	timestamp := time.Now().UnixNano() / 1000000
	payload := params.AppBundleID + sep +
		AppleKeyId + sep +
		params.ProductIdentifier + sep +
		params.OfferID + sep +
		params.ApplicationUsername + sep +
		nonce + sep +
		fmt.Sprintf("%v", timestamp)
	hash := sha256.Sum256([]byte(payload))
	sig, err := privateKey.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		return SignResult{}, err
	}

	return SignResult{
		KeyID:     AppleKeyId,
		Nonce:     nonce,
		Timestamp: timestamp,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

func Verify(params *SignParams, result *SignResult) bool {
	payload := params.AppBundleID + sep +
		AppleKeyId + sep +
		params.ProductIdentifier + sep +
		params.OfferID + sep +
		params.ApplicationUsername + sep +
		result.Nonce + sep +
		fmt.Sprintf("%v", result.Timestamp)

	hash := sha256.Sum256([]byte(payload))

	var esig struct {
		R, S *big.Int
	}
	sig, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return false
	}
	_, err = asn1.Unmarshal(sig, &esig)
	if err != nil {
		return false
	}

	return ecdsa.Verify(&privateKey.PublicKey, hash[:], esig.R, esig.S)
}
