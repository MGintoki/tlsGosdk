package cipherSuites

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

const (
	privateKey = `-----BEGIN  WUMAN RSA PRIVATE KEY -----
MIIEpQIBAAKCAQEArDuxlkVpBB4zPoNzBh9F0OLeR8kk/8/ewryuVlj2/SM5gLaN
I8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhhLreB566m+H4TrobaRfrhe2ZQG/E2
8XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzTM1p1XlA1mrJPc7GlDKCRcUiPDn+n
Z67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8NLGMSBW8/zOxNdeC3S+8ni6HjXsj
Wft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7A0+CrDSvVGp9QPuQhdCyf6INduHp
INzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJnwIDAQABAoIBAQCOcG/WD2Fifndy
49Nk5MggkP+z7q4iwg9AjjrAPqNFhrQvtsnTJm8AtNu5bA8aO9onZBF+lpzx0R7r
Y7GWU4ZL1Igiy1ZbfCla1Tv/VBTWsS7fbQY7gDju2lCYVxH7gX7jQ6SskG900b9q
A2EFGOSyO8WFUmCCp6T90ZTmdITUYgk8iNO2bhte0ypHVef3MUrxAu6YnQUIrFIA
zP+Aq09He68ddun38uymOrIpglL5c9pQBpMLZCz866kYfHiyGbGEUyJ60rpqj6u8
1GHDIxtpM9ltwig8nygwrDmkkJw+t1QkxhIPMNbI9B7S/lzMFIZG25puWdoOg5K+
El5zRbBBAoGBAOOQtxYWKQLIDPvddbdGD3qA9J3gAOlGUO8l4V558i+aCdfwZ9NX
O744TvqlMc4P3BrqAt5naKo4tV8mxHz7bo846Y/zOAj/eO72s3Acrn0H6Pmakndn
2TIvl04m6cqoIISoorBuN9KwUImhzar1+0xxuMK2yjChGQivb4wSuC9bAoGBAMHB
CGMSaW73Cv8VBb+9RbLBOUmD7JZcqg5ENvPb50YVEVKpCre/CF1G4QZnbg85FRR3
LjG+NLJBk1dQn4EEE44iwhEGgj1jdO4lCziuJoAWTsFwHpTiJDhdW78ZNsgHejC+
tNrQB0y+Uah5c06p4VJu/kSbr/MoFzenqiva3wYNAoGBAIbZ1uTrtNnFGoyWK4+z
oLCDgnGbsG6MEKHm3KpTsUSsD3E7MQt4Ahsy2vqEsgLeOxxn19NbjBZzDGeaXY2C
oX2VyDJZerc6TLuuzZ5+IJhO+6wOAQVpMLggo5TYUmqZPsvd8qqCZeogOVmV3H6W
zZf7O/WGxEIU9PTEoWFsJmFJAoGAFpD1+hv93ae2Rylapw9TW9N3aaGM36JhSBIX
2GUnVZlEkD0R+36rabnEoatQPUOnud97qN1/Y7eRgpzoRu2DnY1czwDUEHRR/R6h
ZPObllWCzLLTTQHduBbfha1ZHQkJ6T188PNDtmOAPUAP9vyAOsqkoLcFUiu8MIY9
oqf2S80CgYEAppFtMX0bCbBZJwMWY4oskk1IC4y99ogEL0itMGOyxcaVffKRJtkD
v3jylXAUVxu55chy0rbPe4jtgDx/E5k1ZkTNTytOoB1VGblmuGtKWYQe3ITS6V0x
ss2ih/aaR47pzNvK5Z6G/AKtkAy6EubKKGBgMfg+9iiX/IbweFvvb7Y=
-----END  WUMAN RSA PRIVATE KEY -----`
	publicKey = `-----BEGIN  WUMAN  RSA PUBLIC KEY -----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDuxlkVpBB4zPoNzBh9F
0OLeR8kk/8/ewryuVlj2/SM5gLaNI8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhh
LreB566m+H4TrobaRfrhe2ZQG/E28XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzT
M1p1XlA1mrJPc7GlDKCRcUiPDn+nZ67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8
NLGMSBW8/zOxNdeC3S+8ni6HjXsjWft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7
A0+CrDSvVGp9QPuQhdCyf6INduHpINzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJ
nwIDAQAB
-----END  WUMAN  RSA PUBLIC KEY -----`

	pemPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS5GGSzGeKi/Eol9L
Us7tqD2TJUBZT06sIa2QmBISir2hRANCAASTqPCwtLPflFMip43pzqFKArV/JSsF
7aJodHfgvn4NDqPZQyKLaGjkdtrM7FLpNxsZ66juruABc/vVYtmf2Z6U
-----END PRIVATE KEY-----
`
	pemPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk6jwsLSz35RTIqeN6c6hSgK1fyUr
Be2iaHR34L5+DQ6j2UMii2ho5HbazOxS6TcbGeuo7q7gAXP71WLZn9melA==
-----END PUBLIC KEY-----
`
)

func TestNewRSA_AES_CBC_SHA256Model(t *testing.T) {
	tests := []struct {
		name string
		want *RSA_AES_CBC_SHA256
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRSA_AES_CBC_SHA256Model(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRSA_AES_CBC_SHA256Model() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPKCS5Padding(t *testing.T) {
	type args struct {
		plainText []byte
		blockSize int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCS5Padding(tt.args.plainText, tt.args.blockSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCS5Padding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPKCS5UnPadding(t *testing.T) {
	type args struct {
		plainText []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PKCS5UnPadding(tt.args.plainText)
			if (err != nil) != tt.wantErr {
				t.Errorf("PKCS5UnPadding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCS5UnPadding() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSA_AES_CBC_SHA256_AsymmetricKeyDecrypt(t *testing.T) {

}

func TestRSA_AES_CBC_SHA256_AsymmetricKeyEncrypt(t *testing.T) {
	rsa := NewRSA_AES_CBC_SHA256Model()
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)
	plaintext := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程dadsad c床前明月光，疑是地上霜,举头望明月，低头学编程dadsad c" +
		"床前明月光，疑是地上霜,举头望明月，低头学编程dadsad c")
	// 直接传入明文和公钥加密得到密文
	fmt.Println(len(plaintext))
	fmt.Println("hfjkashjfjak")
	crypttext, err := rsa.AsymmetricKeyEncrypt(plaintext, publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("密文", hex.EncodeToString(crypttext))
	// 解密操作，直接传入密文和私钥解密操作，得到明文
	plaintext, err = rsa.AsymmetricKeyDecrypt(crypttext, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("明文：", string(plaintext))

}

func TestRSA_AES_CBC_SHA256_AsymmetricKeySign(t *testing.T) {

}

func TestRSA_AES_CBC_SHA256_AsymmetricKeyVerify(t *testing.T) {
	rsa := NewRSA_AES_CBC_SHA256Model()
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)
	msg := []byte("RSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfs" +
		"dfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfs" +
		"RSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfds" +
		"fdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfs" +
		"RSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfds" +
		"fsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfs")
	signmsg, err := rsa.AsymmetricKeySign(msg, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("RSA数字签名的消息为：", hex.EncodeToString(signmsg))

	// 验证数字签名正不正确
	result := rsa.AsymmetricKeyVerifySign(msg, signmsg, publicKey)
	if result { // 如果result返回的是 true 那么就是本人签名，否则不是，只有私钥加密，相对的公钥验证才可以认为是本人
		fmt.Println("RSA数字签名正确，是本人")
	} else {
		fmt.Println("RSA数字签名错误，不是本人")
	}
}

func TestRSA_AES_CBC_SHA256_CreateMAC(t *testing.T) {
	rsa := NewRSA_AES_CBC_SHA256Model()
	msg := []byte("RSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfs" +
		"RSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfs" +
		"RSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfsRSA数字签名测试sdfsdfsfsfsdfsfsfsfdsfdsfsfs")
	mac := rsa.CreateMAC(msg)
	fmt.Println(string(mac))
}

func TestRSA_AES_CBC_SHA256_CreateSymmetricKey(t *testing.T) {
	rsa := NewRSA_AES_CBC_SHA256Model()
	key := rsa.CreateSymmetricKey()
	fmt.Println(string(key))
}

func TestRSA_AES_CBC_SHA256_SymmetricKeyEncrypt(t *testing.T) {
	rsa := NewRSA_AES_CBC_SHA256Model()
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言 床前明月光，疑是地上霜，举头望明月，学习go语言 " +
		"床前明月光，疑是地上霜，举头望明月，学习go语言 床前明月光，疑是地上霜，举头望明月，学习go语言 " +
		"床前明月光，疑是地上霜，举头望明月，学习go语言 床前明月光，疑是地上霜，举头望明月，学习go语言 " +
		"床前明月光，疑是地上霜，举头望明月，学习go语言 床前明月光，疑是地上霜，举头望明月，学习go语言 " +
		"床前明月光，疑是地上霜，举头望明月，学习go语言 床前明月光，疑是地上霜，举头望明月，学习go语言 " +
		"床前明月光，疑是地上霜，举头望明月，学习go语言 床前明月光，疑是地上霜，举头望明月，学习go语言 ")
	fmt.Println("明文为：", string(plaintext))

	// 传入明文和自己定义的密钥，密钥为16字节 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	cryptText, err := rsa.SymmetricKeyEncrypt(plaintext, []byte("vy0gr36k34sn0focji6m6dbfvy2m23iy"))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))

	// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	newplaintext, err := rsa.SymmetricKeyDecrypt(cryptText, []byte("vy0gr36k34sn0focji6m6dbfvy2m23iy"))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("AES的CBC模式解密完：", string(newplaintext))
}
