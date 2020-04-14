package cipherSuites

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/pretty66/gosdk"
	"github.com/pretty66/gosdk/errno"
	"log"
	"runtime"
)

var _RSA_AES_CBC_SHA256 *RSA_AES_CBC_SHA256

func NewRSA_AES_CBC_SHA256Model() *RSA_AES_CBC_SHA256 {
	if _RSA_AES_CBC_SHA256 == nil {
		_RSA_AES_CBC_SHA256 = &RSA_AES_CBC_SHA256{}
	}
	return _RSA_AES_CBC_SHA256
}

func (c *RSA_AES_CBC_SHA256) CipherSuiteKey() string {
	return gosdk.RSA_AES_CBC_SHA256_KEY
}

const (
	KEY_LENGTH = 32
	IVAES      = "IVAESIVAESIVAESI"
)

type RSA_AES_CBC_SHA256 struct {
}

func (c *RSA_AES_CBC_SHA256) CreateSymmetricKey() (symmetricKey []byte) {
	return gosdk.GetRandom(KEY_LENGTH)
}

func (c *RSA_AES_CBC_SHA256) AsymmetricKeyEncrypt(plainText, publicKey []byte) (cipherText []byte, err error) {
	block, _ := pem.Decode(publicKey)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKeyParse := publicKeyInterface.(*rsa.PublicKey)
	cipherText, err = rsa.EncryptPKCS1v15(rand.Reader, publicKeyParse, plainText)
	return
}

func (c *RSA_AES_CBC_SHA256) AsymmetricKeyDecrypt(cipherText, privateKey []byte) (plainText []byte, err error) {
	block, _ := pem.Decode(privateKey)

	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	privateKeyParse, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, err
	}
	plainText, err = rsa.DecryptPKCS1v15(rand.Reader, privateKeyParse, cipherText)
	return
}

func (c *RSA_AES_CBC_SHA256) AsymmetricKeySign(data, privateKey []byte) (sign []byte, err error) {
	block, _ := pem.Decode(privateKey)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	privateKeyParse, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	myHash := sha256.New()
	myHash.Write(data)
	hashed := myHash.Sum(nil)
	sign, err = rsa.SignPKCS1v15(rand.Reader, privateKeyParse, crypto.SHA256, hashed)
	return
}

func (c *RSA_AES_CBC_SHA256) AsymmetricKeyVerifySign(data, sign, publicKey []byte) (flag bool) {
	block, _ := pem.Decode(publicKey)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	publicInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	publicKeyParse := publicInterface.(*rsa.PublicKey)
	myHash := sha256.New()
	myHash.Write(data)
	hashed := myHash.Sum(nil)
	result := rsa.VerifyPKCS1v15(publicKeyParse, crypto.SHA256, hashed, sign)
	return result == nil
}

func (c *RSA_AES_CBC_SHA256) SymmetricKeyEncrypt(plainText, symmetricKey []byte) (cipherText []byte, err error) {
	if len(symmetricKey) != 16 && len(symmetricKey) != 24 && len(symmetricKey) != 32 {
		return nil, errno.SYMMETRIC_KEY_INVALID.Add("must in 16 24 32")
	}
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}
	paddingText := PKCS5Padding(plainText, block.BlockSize())
	iv := []byte(IVAES)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText = make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return cipherText, nil
}

func (c *RSA_AES_CBC_SHA256) SymmetricKeyDecrypt(cipherText, symmetricKey []byte) (plainText []byte, err error) {
	if len(symmetricKey) != 16 && len(symmetricKey) != 24 && len(symmetricKey) != 32 {
		return nil, errno.SYMMETRIC_KEY_INVALID.Add("must in 16 24 32")
	}
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}
	iv := []byte(IVAES)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	paddingText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(paddingText, cipherText)

	plainText, err = PKCS5UnPadding(paddingText)
	return
}

func (c *RSA_AES_CBC_SHA256) CreateMAC(data []byte) (MAC []byte) {
	digest := sha256.New()
	digest.Write(data)
	sum := digest.Sum(nil)
	MAC = []byte(hex.EncodeToString(sum))
	return
}

func PKCS5Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}

func PKCS5UnPadding(plainText []byte) ([]byte, error) {
	length := len(plainText)
	number := int(plainText[length-1])
	if number >= length {
		return nil, errno.PADDING_INVALID
	}
	return plainText[:length-number], nil
}