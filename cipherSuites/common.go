package cipherSuites

import (
	"bytes"
	"github.com/pborman/uuid"
	"github.com/pretty66/gosdk/errno"
	"math/rand"
	"strings"
	"time"
)

//定义cipherSuites包的常量以及通用方法

//定义加密套件映射
var CIPHER_SUITE_MAP = map[string]int{
	"RSA_AES_CBC_SHA256":      100,
	"ECDSA_AES256_CBC_SHA256": 101,
}

const DEFAULT_CIPHER_SUITE = 100

func GetAllCipherSuites() map[string]int {
	return CIPHER_SUITE_MAP
}

const KEY_LENGTH = 32

var ResumptionMap map[int]bool = map[int]bool{
	CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]: true,
}

type SignIns struct {
	RSASign  []byte
	ECCRText []byte
	ECCSText []byte
}

func CreateSessionId() string {
	return NewUuid()
}

func NewUuid() string {
	uuidStr := uuid.NewRandom().String()
	return strings.ReplaceAll(uuidStr, "-", "")
}

//生成指定长度的字符串（包括数字）
func GetRandom(l int) []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return result
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

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
