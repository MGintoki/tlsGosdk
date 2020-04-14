package cipherSuites

type RSA_AES_CBC_SHA256 struct {
}

func (c *RSA_AES_CBC_SHA256) name() string {
	return "RSA_AES_CBC_SHA256"
}

var _RSA_AES_CBC_SHA256 *RSA_AES_CBC_SHA256

func NewRSA_AES_CBC_SHA256() *RSA_AES_CBC_SHA256 {
	if _RSA_AES_CBC_SHA256 == nil {
		_RSA_AES_CBC_SHA256 = &RSA_AES_CBC_SHA256{}
	}
	return _RSA_AES_CBC_SHA256
}
