package gosdk

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/wumansgy/goEncrypt"
	"testing"
)

func TestSha(t *testing.T) {
	hash := goEncrypt.Sha512Hex([]byte("test"))
	fmt.Println(hash)
}

func TestAES(t *testing.T) {
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
	fmt.Println("明文为：", string(plaintext))

	// 传入明文和自己定义的密钥，密钥为16字节 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	cryptText, err := goEncrypt.AesCbcEncrypt(plaintext, []byte("wumansgygoaescrywumansgygoaescry"))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))

	// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	newplaintext, err := goEncrypt.AesCbcDecrypt(cryptText, []byte("wumansgygoaescrywumansgygoaescry"))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("AES的CBC模式解密完：", string(newplaintext))
}

func TestFilePutContents(t *testing.T) {
	type args struct {
		path    string
		content []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := FilePutContents(tt.args.path, tt.args.content); (err != nil) != tt.wantErr {
				t.Errorf("FilePutContents() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test11_1(t *testing.T) {

}

func NewLenChars(length int, chars []byte) string {
	if length == 0 {
		return ""
	}
	clen := len(chars)
	if clen < 2 || clen > 256 {
		panic("Wrong charset length for NewLenChars()")
	}
	maxrb := 255 - (256 % clen)
	b := make([]byte, length)
	r := make([]byte, length+(length/4)) // storage for random bytes.
	i := 0
	for {
		if _, err := rand.Read(r); err != nil {
			panic("Error reading random bytes: " + err.Error())
		}
		for _, rb := range r {
			c := int(rb)
			if c > maxrb {
				continue // Skip this number to avoid modulo bias.
			}
			b[i] = chars[c%clen]
			i++
			if i == length {
				return string(b)
			}
		}
	}
}
