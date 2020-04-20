package gosdk

import (
	"github.com/pborman/uuid"
	"github.com/pretty66/gosdk/cipherSuites"
	"math/rand"
	"strings"
	"time"
)

//type SymmetricKey struct {
//	SessionId    string    `json:"sessionId"`
//	IsResumption bool      `json:"isResumption"`
//	KeyType      int       `json:"keyType"`
//	Key          []byte    `json:"key"`
//	CipherSuite  int       `json:"cipherSuite"`
//	CreatedAt    time.Time `json:"createdAt"`
//	ExpiresAT    time.Time `json:"expiresAt"`
//}

func CreateSymmetricKey(cipherSuite int, randoms []string) (symmetricKey []byte) {

	switch cipherSuite {
	case cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]:
		symmetricKey = GetRandom(KEY_LENGTH)

	}
	return symmetricKey
}

const KEY_LENGTH = 32

//指定通信密钥的类型
const (
	AES_CBC = 1
)

var ResumptionMap map[int]bool = map[int]bool{
	cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"]: true,
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
