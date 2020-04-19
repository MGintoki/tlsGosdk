package gosdk

import (
	"encoding/json"
	"github.com/pretty66/gosdk/cipherSuites"
	"github.com/pretty66/gosdk/errno"
)

//将接口嵌套到结构体中，方便以后结构体的拓展
type CipherSuite struct {
	CipherSuiteInterface CipherSuiteInterface `json:"cipherSuiteInterface"`
}

type CipherSuiteInterface interface {
	CipherSuiteKey() (key int)                                        //获取加密套件KEY
	CreateSymmetricKey(randoms []string) (symmetricKey *SymmetricKey) // 生成通信密钥
	CreateMAC(data []byte) []byte
	AsymmetricKeyEncrypt(plainText, publicKey []byte) (cipherText []byte, err error)   //公钥加密
	AsymmetricKeyDecrypt(cipherText, privateKey []byte) (plainText []byte, err error)  // 私钥解密
	AsymmetricKeySign(data, privateKey []byte) (sign []byte, err error)                //私钥签名
	AsymmetricKeyVerifySign(data, sign, publicKey []byte) (flag bool)                  //公钥验签
	SymmetricKeyEncrypt(plainText, symmetricKey []byte) (cipherText []byte, err error) //对称密钥加密
	SymmetricKeyDecrypt(cipherText, symmetricKey []byte) (plainText []byte, err error) //对称密钥解密
}

var _cipherSuite *CipherSuite
var _currentCipherSuite int

func NewCipherSuiteModel(cipherSuitCode int) *CipherSuite {
	if _currentCipherSuite == 0 || _currentCipherSuite != cipherSuitCode {
		switch cipherSuitCode {
		case RSA_AES_CBC_SHA256:
			csIns := cipherSuites.NewRSA_AES_CBC_SHA256Model()
			return &CipherSuite{CipherSuiteInterface: csIns}
		}
	}
	return _cipherSuite
}

//返回对称密钥加密的MAC
func CreateNegotiateMAC(tlsConfig *TlsConfig) (MAC string, err error) {
	cs := NewCipherSuiteModel(tlsConfig.CipherSuite)
	//将来需要加一个检测 检测handshakeMsgs中是否含有三个消息
	tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE].ClientKeyExchange.MAC = ""
	chByte, err := json.Marshal(tlsConfig.HandshakeMsgs[CLIENT_HELLO_CODE].ClientHello)
	if err != nil {
		return MAC, errno.JSON_ERROR.Add("Client Hello Marshal error")
	}
	chMAC := cs.CipherSuiteInterface.CreateMAC(chByte)
	shByte, err := json.Marshal(tlsConfig.HandshakeMsgs[SERVER_RECEIVED_CLIENT_HELLO_STATE].ServerHello)
	if err != nil {
		return MAC, errno.JSON_ERROR.Add("Server Hello Marshal error")
	}
	shMAC := cs.CipherSuiteInterface.CreateMAC(shByte)
	ckeByte, err := json.Marshal(tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE].ClientKeyExchange)
	if err != nil {
		return MAC, errno.JSON_ERROR.Add("Client Key Exchange Marshal error")
	}
	ckeMAC := cs.CipherSuiteInterface.CreateMAC(ckeByte)
	var totalMAC []byte
	totalMAC = append(totalMAC, chMAC...)
	totalMAC = append(totalMAC, shMAC...)
	totalMAC = append(totalMAC, ckeMAC...)
	MACByte, err := cs.CipherSuiteInterface.SymmetricKeyEncrypt(totalMAC, tlsConfig.SymmetricKey.Key)
	if err != nil {
		return MAC, err
	}
	MAC = string(MACByte)

	return
}

func CreateAppDataMAC(data map[string]interface{}) string {
	return ""
}

const UUID_LENGTH = 32

const (
	RSA_AES_CBC_SHA256 = 1
)
