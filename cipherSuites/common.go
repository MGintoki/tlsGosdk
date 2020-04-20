package cipherSuites

import ()

//定义cipherSuites包的常量以及通用方法

//定义加密套件映射
var CIPHER_SUITE_MAP = map[string]int{
	"RSA_AES_CBC_SHA256": 100,
}

func GetAllCipherSuites() map[string]int {
	return CIPHER_SUITE_MAP
}
