package gosdk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/pretty66/gosdk/cipherSuites"
	"github.com/pretty66/gosdk/errno"
	"github.com/wumansgy/goEncrypt"
)

//将接口嵌套到结构体中，方便以后结构体的拓展
type CipherSuite struct {
	CipherSuiteInterface CipherSuiteInterface `json:"cipherSuiteInterface"`
}

type CipherSuiteInterface interface {
	CipherSuiteKey() (key int)                        //获取加密套件KEY
	CreateSymmetricKey(randoms []string) (key []byte) // 生成通信密钥
	CreateMAC(data []byte) []byte
	VerifyCert(cert []byte, certChain []byte, publicKey []byte) (out bool, err error)
	AsymmetricKeyEncrypt(plainText, publicKey []byte) (cipherText []byte, err error)   //公钥加密
	AsymmetricKeyDecrypt(cipherText, privateKey []byte) (plainText []byte, err error)  // 私钥解密
	AsymmetricKeySign(data, privateKey []byte) (sign []byte, err error)                //私钥签名
	AsymmetricKeyVerifySign(data, sign, publicKey []byte) (flag bool, err error)       //公钥验签
	SymmetricKeyEncrypt(plainText, symmetricKey []byte) (cipherText []byte, err error) //对称密钥加密
	SymmetricKeyDecrypt(cipherText, symmetricKey []byte) (plainText []byte, err error) //对称密钥解密
}

var _cipherSuite *CipherSuite
var _currentCipherSuiteCode int

func NewCipherSuiteModel(cipherSuitCode int) *CipherSuite {
	if _currentCipherSuiteCode == 0 || _currentCipherSuiteCode != cipherSuitCode {
		switch cipherSuitCode {
		case cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]:
			_cipherSuite = &CipherSuite{CipherSuiteInterface: cipherSuites.NewRSA_AES_CBC_SHA256Model()}
			_currentCipherSuiteCode = cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]
		//return &CipherSuite{CipherSuiteInterface: csIns}
		case cipherSuites.CIPHER_SUITE_MAP["ECDSA_AES256_CBC_SHA256"]:
			_cipherSuite = &CipherSuite{CipherSuiteInterface: cipherSuites.NewECDSA_AES256_CBC_SHA256Model()}
			_currentCipherSuiteCode = cipherSuites.CIPHER_SUITE_MAP["ECDSA_AES256_CBC_SHA256"]
		}

	}
	return _cipherSuite
}

//返回对称密钥加密的MAC
//原料为存储在tlsConfig里的三个消息 ： client hello/server hello/client key exchange
func CreateNegotiateMAC(tlsConfig *TlsConfig) (MAC []byte, err error) {
	cs := NewCipherSuiteModel(tlsConfig.CipherSuite)
	//将来需要加一个检测 检测handshakeMsgs中是否含有三个消息
	tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE].ClientKeyExchange.MAC = ""
	chByte, err := json.Marshal(tlsConfig.HandshakeMsgs[CLIENT_HELLO_CODE].ClientHello)
	if err != nil {
		return MAC, errno.JSON_ERROR.Add("Client Hello Marshal error")
	}
	shByte, err := json.Marshal(tlsConfig.HandshakeMsgs[SERVER_HELLO_CODE].ServerHello)
	if err != nil {
		return MAC, errno.JSON_ERROR.Add("Server Hello Marshal error")
	}
	//client CreateMAC时，client key exchange的MAC是空的，所以服务端这里生成时也要置MAC为空
	tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE].ClientKeyExchange.MAC = ""
	ckeByte, err := json.Marshal(tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE].ClientKeyExchange)
	if err != nil {
		return MAC, errno.JSON_ERROR.Add("Client Key Exchange Marshal error")
	}
	var totalByte []byte
	totalByte = append(totalByte, chByte...)
	totalByte = append(totalByte, shByte...)
	totalByte = append(totalByte, ckeByte...)
	totalMAC := cs.CipherSuiteInterface.CreateMAC(totalByte)

	return totalMAC, err
}

func CreateAppDataMAC(data map[string]interface{}) string {
	return ""
}

const UUID_LENGTH = 32

//这两个函数是无格式密钥（CA那边的密钥拿过来）的加密解密
func AsymmetricKeyEncrypt(plainText, publicKey []byte) (cipherText []byte, err error) {
	block, _ := pem.Decode(publicKey)
	publicKeyBlock, err := x509.ParsePKIXPublicKey(block.Bytes)
	ecdsaPublicKey, ok := publicKeyBlock.(*ecdsa.PublicKey)
	if !ok {
		return cipherText, errno.ASYMMETRIC_PARSE_ERROR.Add("public key can not converse to ecdsa type")
	}
	publicKeyParse := goEncrypt.ImportECDSAPublic(ecdsaPublicKey)
	cipherText, err = goEncrypt.Encrypt(rand.Reader, publicKeyParse, plainText, nil, nil)
	return
}

func AsymmetricKeyDecrypt(cipherText, privateKey []byte) (plainText []byte, err error) {
	block, _ := pem.Decode(privateKey)

	privateKeyBlock, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return plainText, errno.ASYMMETRIC_PARSE_ERROR.Add(err.Error())
	}
	ecdsaPriKey := privateKeyBlock.(*ecdsa.PrivateKey)
	eciesPrivateKey := goEncrypt.ImportECDSA(ecdsaPriKey)
	plainText, err = eciesPrivateKey.Decrypt(cipherText, nil, nil)
	return
}
