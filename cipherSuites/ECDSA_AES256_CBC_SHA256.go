package cipherSuites

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/pretty66/gosdk/errno"
	"github.com/wumansgy/goEncrypt"
	"log"
	"math/big"
	"runtime"
)

var _ECDSA_AES256_CBC_SHA256 *ECDSA_AES256_CBC_SHA256

type ECDSA_AES256_CBC_SHA256 struct {
}

func NewECDSA_AES256_CBC_SHA256Model() *ECDSA_AES256_CBC_SHA256 {
	if _ECDSA_AES256_CBC_SHA256 == nil {
		_ECDSA_AES256_CBC_SHA256 = &ECDSA_AES256_CBC_SHA256{}
	}
	return _ECDSA_AES256_CBC_SHA256
}

func (c *ECDSA_AES256_CBC_SHA256) CipherSuiteKey() (key int) {
	return CIPHER_SUITE_MAP["ECDSA_AES256_CBC_SHA256"]
}

func (c *ECDSA_AES256_CBC_SHA256) CreateSymmetricKey(randoms []string) (key []byte) {
	return GetRandom(KEY_LENGTH)
}

func (c *ECDSA_AES256_CBC_SHA256) CreateMAC(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	sum := digest.Sum(nil)
	MAC := []byte(hex.EncodeToString(sum))
	return MAC
}

func (c *ECDSA_AES256_CBC_SHA256) VerifyCert(cert []byte, certChain []byte, publicKey []byte) (out bool, err error) {
	return true, err
}

func (c *ECDSA_AES256_CBC_SHA256) AsymmetricKeyEncrypt(plainText, publicKey []byte) (cipherText []byte, err error) {
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
	tempPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	publicKey1 := tempPublicKey.(*ecdsa.PublicKey)
	// Convert to the public key in the ecies package in the ethereum package
	publicKey2 := goEncrypt.ImportECDSAPublic(publicKey1)
	crypttext, err := goEncrypt.Encrypt(rand.Reader, publicKey2, plainText, nil, nil)

	return crypttext, err
}

func (c *ECDSA_AES256_CBC_SHA256) AsymmetricKeyDecrypt(cipherText, privateKey []byte) (plainText []byte, err error) {
	block, _ := pem.Decode(privateKey)
	tempPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errno.ASYMMETRIC_PARSE_ERROR.Add(err.Error())
	}
	// Decode to get the private key in the ecdsa package
	// Convert to the private key in the ecies package in the ethereum package
	ecdsaPivateKey := goEncrypt.ImportECDSA(tempPrivateKey)

	plainText, err = ecdsaPivateKey.Decrypt(cipherText, nil, nil)
	if err != nil {
		return nil, errno.ASYMMETRIC_DECRYPT_ERROR.Add(err.Error())
	}
	return plainText, nil
}

func (c *ECDSA_AES256_CBC_SHA256) AsymmetricKeySign(data, privateKey []byte) (sign []byte, err error) {
	block, _ := pem.Decode(privateKey)
	privateKeyParse, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return sign, err
	}
	myhash := sha256.New()
	myhash.Write(data)
	resultHash := myhash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKeyParse, resultHash)
	if err != nil {
		return sign, err
	}

	rText, err := r.MarshalText()
	if err != nil {
		return sign, err
	}
	sText, err := s.MarshalText()
	if err != nil {
		return sign, err
	}
	signIns := SignIns{
		ECCRText: rText,
		ECCSText: sText,
	}
	signInsMarshal, err := json.Marshal(signIns)
	if err != nil {
		return sign, errno.JSON_ERROR.Add("SignIns Marshal Error")
	}
	return signInsMarshal, nil

}

func (c *ECDSA_AES256_CBC_SHA256) AsymmetricKeyVerifySign(data, sign, publicKey []byte) (flag bool, err error) {
	block, _ := pem.Decode(publicKey)
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	ecdsaPublicKey := publicKeyInterface.(*ecdsa.PublicKey)
	myhash := sha256.New()
	myhash.Write(data)
	resultHash := myhash.Sum(nil)

	var r, s big.Int
	var signIns SignIns
	err = json.Unmarshal(sign, &signIns)
	if err != nil {
		return false, errno.JSON_ERROR.Add("SignIns Unmarshal Error")
	}
	err = r.UnmarshalText(signIns.ECCRText)
	if err != nil {
		return false, errno.ASYMMETRIC_PARSE_ERROR.Add(err.Error())
	}
	err = s.UnmarshalText(signIns.ECCSText)
	if err != nil {
		return false, errno.ASYMMETRIC_PARSE_ERROR.Add(err.Error())
	}
	result := ecdsa.Verify(ecdsaPublicKey, resultHash, &r, &s)
	return result, err
}

func (c *ECDSA_AES256_CBC_SHA256) SymmetricKeyEncrypt(plainText, symmetricKey []byte) (cipherText []byte, err error) {
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

func (c *ECDSA_AES256_CBC_SHA256) SymmetricKeyDecrypt(cipherText, symmetricKey []byte) (plainText []byte, err error) {
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
