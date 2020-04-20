package gosdk

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/wumansgy/goEncrypt"
	"log"
	"reflect"
	"testing"
	"time"
)

func TestSha(t *testing.T) {
	//hash := goEncrypt.Sha512Hex([]byte("test"))
	//fmt.Println(hash)
}

func TestStruct(t *testing.T) {
	//cs := &CipherSuite{}
	//cs_rsa := cipherSuites.NewRSA_AES_CBC_SHA256Model()
	//cs.CipherSuiteInterface = cs_rsa
	//csi := &CipherSuiteInterface()
	//plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
	//fmt.Println("明文为：", string(plaintext))
	//cryptText, err := (plaintext, []byte("wumansgygoaescrywumansgygoaescry"))
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))

}

func TestAES(t *testing.T) {
	//plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
	//fmt.Println("明文为：", string(plaintext))
	//
	//// 传入明文和自己定义的密钥，密钥为16字节 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	//cryptText, err := goEncrypt.AesCbcEncrypt(plaintext, []byte("wumansgygoaescrywumansgygoaescry"))
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))
	//
	//// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	//newplaintext, err := goEncrypt.AesCbcDecrypt(cryptText, []byte("wumansgygoaescrywumansgygoaescry"))
	//if err != nil {
	//	fmt.Println(err)
	//}
	//
	//fmt.Println("AES的CBC模式解密完：", string(newplaintext))
}

type Handshake2 struct {
	Version       string    `json:"version"`
	HandshakeType int       `json:"handshakeType"` //握手类型，是协商还是警告
	ActionCode    int       `json:"actionCode"`
	SessionId     string    `json:"sessionId"`
	SendTime      time.Time `json:"sendTime"` //发送时间

	//初始化HandShake时，根据handshakeCode指定了生成下面具体的消息

	ClientKeyExchange *ClientKeyExchange2 `json:"clientKeyExchange"`
}

type ClientKeyExchange2 struct {
	SymmetricKey []byte `json:"symmetricKey"`
	Random       string `json:"random"`
	MAC          []byte `json:"MAC"`
}

type SymmetricKey2 struct {
	SessionId    string    `json:"sessionId"`
	IsResumption bool      `json:"isResumption"`
	KeyType      int       `json:"keyType"`
	Key          []byte    `json:"key"`
	CipherSuite  int       `json:"cipherSuite"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAT    time.Time `json:"expiresAt"`
}

func TestZ(t *testing.T) {
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)

	plaintext := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程 床前明月光，疑是地上霜,举头望明月，低头学编程")
	// 直接传入明文和公钥加密得到密文
	crypttext, err := goEncrypt.RsaEncrypt(plaintext, publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("密文", hex.EncodeToString(crypttext))
	// 解密操作，直接传入密文和私钥解密操作，得到明文
	plaintext, err = goEncrypt.RsaDecrypt(crypttext, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("明文：", string(plaintext))
}

func TestPEM(t *testing.T) {
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)
	//sk2 := &SymmetricKey2{
	//	SessionId:    "",
	//	IsResumption: false,
	//	KeyType:      100,
	//	Key:          []byte("abcdefghijklmnopqrs"),
	//	CipherSuite:  100,
	//	CreatedAt:    time.Time{},
	//	ExpiresAT:    time.Time{},
	//}
	ck2 := &ClientKeyExchange2{
		SymmetricKey: []byte("sdjflsjddsdfsdfsdfsfsdfklfjklsjfsjdlkjfksl"),
		Random:       "",
		MAC:          []byte("kfdjlsjflsjldfjsljflksjl"),
	}
	hs2 := Handshake2{
		Version:           "",
		HandshakeType:     0,
		ActionCode:        0,
		SessionId:         "",
		SendTime:          time.Time{},
		ClientKeyExchange: ck2,
	}
	b, err := json.Marshal(hs2)
	plaintext := b
	//plaintext := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程")
	// 直接传入明文和公钥加密得到密文
	crypttext, err := NewCipherSuiteModel(100).CipherSuiteInterface.AsymmetricKeyEncrypt(plaintext, publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("密文", hex.EncodeToString(crypttext))
	// 解密操作，直接传入密文和私钥解密操作，得到明文
	plaintext, err = NewCipherSuiteModel(100).CipherSuiteInterface.AsymmetricKeyDecrypt(crypttext, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("明文：", string(plaintext))
}

const (
	PRIVATE_KEY = `-----BEGIN  WUMAN RSA PRIVATE KEY -----
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
	PUBLIC_KEY = `-----BEGIN  WUMAN  RSA PUBLIC KEY -----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDuxlkVpBB4zPoNzBh9F
0OLeR8kk/8/ewryuVlj2/SM5gLaNI8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhh
LreB566m+H4TrobaRfrhe2ZQG/E28XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzT
M1p1XlA1mrJPc7GlDKCRcUiPDn+nZ67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8
NLGMSBW8/zOxNdeC3S+8ni6HjXsjWft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7
A0+CrDSvVGp9QPuQhdCyf6INduHpINzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJ
nwIDAQAB
-----END  WUMAN  RSA PUBLIC KEY -----`
	CERT = ``
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
)

type animal struct {
	animal AnimalInterface
}

type AnimalInterface interface {
	run() string
}

type dog struct {
	name string
}

func (c *dog) run() string {
	return "dog run"
}

func TestIn(t *testing.T) {
	dog := &dog{name: "dog1"}
	fmt.Println(dog.run())
	ai := dog
	fmt.Println(ai.name)
	fmt.Println(ai.run())
	animal := &animal{}
	fmt.Println(reflect.TypeOf(animal.animal))
	animal.animal = ai
	fmt.Println(reflect.TypeOf(animal.animal))
	fmt.Println(animal.animal.run())
}

func TestCertVerify(t *testing.T) {
	certByte := []byte(TEST_CERT)
	p, _ := pem.Decode(certByte)
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {

	}
	caCertByte := []byte(RCA_CERT)
	p2, _ := pem.Decode(caCertByte)
	caCert, err := x509.ParseCertificate(p2.Bytes)
	err = cert.CheckSignatureFrom(caCert)
	if err != nil {

	}

}

func TestCertChain(t *testing.T) {
	block, _ := pem.Decode([]byte(TEST_CERT))
	if block == nil {

	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}

	roots := x509.NewCertPool()

	ok := roots.AppendCertsFromPEM([]byte(RCA_CERT))
	if !ok {
		log.Fatalf("failed to parse roots certificate")
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	chains, err := cert.Verify(opts)
	if err != nil {

	}
	for i, chain := range chains {
		for _, certificate := range chain {
			log.Printf("Chain=%d Subject=%s", i, certificate.Subject)
		}
	}
	fmt.Println(chains)
}

const RCA_CERT = `-----BEGIN CERTIFICATE-----
MIICczCCAhmgAwIBAgIQfB3263XfD17WG0c32jq73jAKBggqhkjOPQQDAjCBgzEL
MAkGA1UEBhMCY24xEDAOBgNVBAgTB2ppYW5nc3UxEDAOBgNVBAcTB25hbmppbmcx
FDASBgNVBAkTC2d1eWFuZ3Rhc2hhMQ8wDQYDVQQREwYxMjM0NTYxCzAJBgNVBAoT
AmNpMQswCQYDVQQLEwJjaTEPMA0GA1UEAxMGY2kuY29tMB4XDTIwMDQxNTEwMDEw
MFoXDTMwMDQxMzEwMDEwMFowgYMxCzAJBgNVBAYTAmNuMRAwDgYDVQQIEwdqaWFu
Z3N1MRAwDgYDVQQHEwduYW5qaW5nMRQwEgYDVQQJEwtndXlhbmd0YXNoYTEPMA0G
A1UEERMGMTIzNDU2MQswCQYDVQQKEwJjaTELMAkGA1UECxMCY2kxDzANBgNVBAMT
BmNpLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH/t5L0ZjJIJaChxIlmT
2Z+qCxqFMBhj6+UCyJ2ShGqX/C5KXiqUZkFeke51TPp6Ekl7XtiHAd0QHmXG0/wn
FTWjbTBrMA4GA1UdDwEB/wQEAwIBpjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwDwYDVR0TAQH/BAUwAwEB/zApBgNVHQ4EIgQg5dF1eDfmu1hGjJc96Bmm
gZg/w/JAhnmKS0nSURpxuAMwCgYIKoZIzj0EAwIDSAAwRQIgJU+h99Gt/bJoK86T
eBs1d8AYvRVJ9Iw5dTkkMyiW130CIQD8BUpe9pim9ap5ne1oUJGxg90KBvMC7QUG
YrmZ+cYXFQ==
-----END CERTIFICATE-----`
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIICwzCCAmmgAwIBAgIUVIR1inLmwy3HzhffK9/VbM7Ei20wCgYIKoZIzj0EAwIw
czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMjAwNDEzMTEzMTAwWhcNMjUwNDEyMTEz
NjAwWjBRMQkwBwYDVQQGEwAxCTAHBgNVBAgTADEJMAcGA1UEBxMAMQkwBwYDVQQK
EwAxDTALBgNVBAsTBG9yZzExFDASBgNVBAMTC2RpZC1hZGZzZmRmMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEI4+mL/Lkx7tjFNzvTFdME9htUdFBMvAtas0wyett
Cz/jMszPU6iSFuhZI2XjTob2QO4g5nK75z2JffAzADRPS6OB/DCB+TAOBgNVHQ8B
Af8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUQdEqxyouVVP8
i1efOQ5yLen97KIwKwYDVR0jBCQwIoAg5xmhZslKvW1mYTAezU8dKZP/boqf68a3
H6pmMF1HhDAwgYYGCCoDBAUGBwgBBHp7ImF0dHJzIjp7ImFjY291bnRJZCI6ImFi
YyIsImhmLkludGVybWVkaWF0ZUNBIjoidHJ1ZSIsIm9yZ19rZXkiOiJvcmdrZXkx
Iiwic3ViT3JnS2V5Ijoib3JnMSIsInN1Yl9vcmdfa2V5Ijoic3ViT3JnS2V5MSJ9
fTAKBggqhkjOPQQDAgNIADBFAiEAmrJ4ZDH+xEGI2WqAsgApsaSxATcjuNOso8G4
Pl3VuewCICHIKph00oLckO/UuTgowfWlEsqD41Dl0LwjuYASUOjB
-----END CERTIFICATE-----
`
