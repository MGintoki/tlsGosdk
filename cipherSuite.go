package gosdk

import "github.com/pretty66/gosdk/cipherSuites"

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

func CreateNegotiateMAC(tlsConfig *TlsConfig) string {
	return ""
}

func CreateAppDataMAC(data map[string]interface{}) string {
	return ""
}

const UUID_LENGTH = 32

const (
	RSA_AES_CBC_SHA256 = 1
)
