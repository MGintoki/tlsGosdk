package gosdk

//将接口嵌套到结构体中，方便以后结构体的拓展
type cipherSuite struct {
	cipherSuite *CipherSuite
}

type CipherSuite interface {
	CipherSuiteKey() (key string)
	CreateSymmetricKey() []byte
	AsymmetricKeyEncrypt(plainText, publicKey []byte) (cipherText []byte, err error)
	AsymmetricKeyDecrypt(cipherText, privateKey []byte) (plainText []byte, err error)
	AsymmetricKeySign(data, privateKey []byte) (sign []byte, err error)
	AsymmetricKeyVerifySign(data, sign, publicKey []byte) (flag bool)
	SymmetricKeyEncrypt(plainText, symmetricKey []byte) (cipherText []byte, err error)
	SymmetricKeyDecrypt(cipherText, symmetricKey []byte) (plainText []byte, err error)
}
