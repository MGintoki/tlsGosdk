package gosdk

//将接口嵌套到结构体中，方便以后结构体的拓展
type cipherSuite struct {
	CipherSuite
}

type CipherSuite interface {
	CreateSymmetricKey() ([]byte, error)
	AsymmetricKeyEncrypt(plainText, publicKey []byte) (cipherText []byte, err error)
	AsymmetricKeyDecrypt(cipherText, privateKey []byte) (plainText []byte, err error)
	AsymmetricKeySign(data, privateKey []byte) (cipherText []byte, err error)
	AsymmetricKeyVerify(data, sign, publicKey []byte) bool
	SymmetricKeyEncrypt(plainText, symmetricKey []byte) ([]byte, error)
	SymmetricKeyDecrypt(cipherText, symmetricKey []byte) ([]byte, error)
	SymmetricKeyCreateMAC(data []byte) string
}
