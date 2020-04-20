package cipherSuites

import (
	"github.com/pborman/uuid"
	"math/rand"
	"strings"
	"time"
)

//定义cipherSuites包的常量以及通用方法

//定义加密套件映射
var CIPHER_SUITE_MAP = map[string]int{
	"RSA_AES_CBC_SHA256": 100,
}

func GetAllCipherSuites() map[string]int {
	return CIPHER_SUITE_MAP
}

const KEY_LENGTH = 32

var ResumptionMap map[int]bool = map[int]bool{
	CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]: true,
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
