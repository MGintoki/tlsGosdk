package cipherSuites

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

func (c *RSA_AES_CBC_SHA256) CipherSuiteKey() int {
	return CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]
}

const (

	//偏移量，相同的明文和密钥，偏移量不同，密钥也会不同
	//偏移量无保密要求，有随机要求
	IVAES = "IVAESIVAESIVAESI"
)

type RSA_AES_CBC_SHA256 struct {
}

func (c *RSA_AES_CBC_SHA256) CreateSymmetricKey(randoms []string) (key []byte) {
	return GetRandom(KEY_LENGTH)
}

func (c *RSA_AES_CBC_SHA256) VerifyCert(cert []byte, certChain [][]byte, publicKey []byte) (out bool, err error) {

	return true, err
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
	RSASign, err := rsa.SignPKCS1v15(rand.Reader, privateKeyParse, crypto.SHA256, hashed)
	signIns := &SignIns{RSASign: RSASign}
	signInsMarshal, err := json.Marshal(signIns)
	if err != nil {
		return sign, errno.JSON_ERROR.Add("SignIns Marshal Error")
	}

	return signInsMarshal, err
}

func (c *RSA_AES_CBC_SHA256) AsymmetricKeyVerifySign(data, sign, publicKey []byte) (flag bool, err error) {
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

	var signIns SignIns
	err = json.Unmarshal(sign, &signIns)
	if err != nil {
		return flag, errno.JSON_ERROR.Add("SignIns Unmarshal Error")
	}
	result := rsa.VerifyPKCS1v15(publicKeyParse, crypto.SHA256, hashed, signIns.RSASign)
	return result == nil, err
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
