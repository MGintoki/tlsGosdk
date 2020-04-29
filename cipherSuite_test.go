package gosdk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/pretty66/gosdk/cipherSuites"
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
	hs := Handshake{
		Version:           "jflsjflsd",
		HandshakeType:     0,
		ActionCode:        0,
		SessionId:         "",
		SendTime:          time.Time{},
		ClientHello:       nil,
		ServerHello:       nil,
		ClientKeyExchange: nil,
		ServerFinished:    nil,
		AppData:           nil,
		ClientCloseNotify: nil,
		Alert:             nil,
	}
	hsByte, err := json.Marshal(hs)
	fmt.Println(hsByte)
	testJson := `{"data":"28c5Oz2uGB5fD6xKWBhz53FL9rzAIJTWT4ojoNXeieLvjd6Kp8rxQymMZmO2GxTjfWhzFVT0jBVPFdd8V59oB4wgx47lM2XM1yJI/1llZ9thjD2KT6a5sSjMmLZukINE+ekRSnzWTYI2qAqxJCTIqftXTTcMQqb13q+1iL7RrTCBr+Pa0EiJN8e1gAF+BedZ5IGKZS04LZXGfurDD4Q/pw==","ss":"ss"}
`
	aa := map[string]interface{}{}
	err = json.Unmarshal([]byte(testJson), &aa)
	if err != nil {

	}
	aaMarshal, err := json.Marshal(aa)
	//fmt.Println("明文为：", string(plaintext))
	cs := NewCipherSuiteModel(100)
	//str := "1234567890abcdef"
	//fmt.Println(len(str))
	// 传入明文和自己定义的密钥，密钥为16字节 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	cryptText, err := cs.CipherSuiteInterface.SymmetricKeyEncrypt(aaMarshal, []byte("1234567890abcdef"))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))
	//cryptText := []byte("28c5Oz2uGB5fD6xKWBhz53FL9rzAIJTWT4ojoNXeieLvjd6Kp8rxQymMZmO2GxTjfWhzFVT0jBVPFdd8V59oB4wgx47lM2XM1yJI/1llZ9thjD2KT6a5sSjMmLZukINE+ekRSnzWTYI2qAqxJCTIqftXTTcMQqb13q+1iL7RrTCBr+Pa0EiJN8e1gAF+BedZ5IGKZS04LZXGfurDD4Q/pw==")

	// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	newplaintext, err := cs.CipherSuiteInterface.SymmetricKeyDecrypt(cryptText, []byte("1234567890abcdef"))
	if err != nil {
		fmt.Println(err)
	}
	var zz interface{}
	err = json.Unmarshal(newplaintext, &zz)
	if err != nil {

	}

	fmt.Println("AES的CBC模式解密完：", string(newplaintext))
}

func TestDecrypt(t *testing.T) {
	cs := NewCipherSuiteModel(100)
	plaintext := []byte("  床前明月光，疑是地上霜，举头望明月，是否 学习go语言sasadfsadjkfklsajdf" +
		"jsldakdjflkjaslkdfjlakjfdljasfkljakldsjf;lksjdlkfj" +
		"wjequrioqu203984-2834-2349 i i fsaasfsf sf saf     " +
		"ajfjasf'jsa'fdjsafjdflkjsaklfjslajfslkfj+jflqkjwelrjoi     sdsfafasdf   ")
	fmt.Println("明文为：", string(plaintext))

	// 传入明文和自己定义的密钥，密钥为16字节 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	cryptText, err := cs.CipherSuiteInterface.SymmetricKeyEncrypt(plaintext, []byte("0123456789abcdef"))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))
	//cryptText = []byte("VHNhWUZGK01MejBkL1kyb1ZiR3JENUlzQXViNXdDazg0RmdqaUpaWHg2Y0hiYldYS3pmL3VEWWJ2MVJqRUJHODJ6WVNHV210K2dLc3QwS0NENDVHUVc4NEU2NmdtaTJPZ2tzT3FDdi85VFVUSG11Mm1hRzViOEpUQkVJc0lrMUxrNnd2N0lFeGg5Z2xnNHhaV2xnU2htNW03azA5ZWhrbW5kVzhFangraUxWVHBQQ004SlpiS0VBRHk1akJpeVFqM2pEL0VBRFdXQnZPNFdYU3pyVWVmTnRPcHB1dUhPRFYrVlNFczNBSkJxaEU1dnY4bFFvcjBUK1lXTy9CSWNaeTliekc2cjJVUFJDL0FweUE2eUVzdG85RjEyaWpFdHY1SU5wejhmbFRWUjNoNnNXTTZydCtEYjI5Nkk4VnhUdEM1NUdQbFpGS0RRUWd2NkJXcmhuTDFzemp4WFlwT3lSWWdwYnVvOXg4REV3dTMvNFhHc3hKcEh4RGFlRmthdU8rWncrWDRsUm5xUVIvMFpIKzd2dWlPbHlpTjFNNWdzekZ3N05NT0hmdDZjSHlmT01lN2dHaUdGbUFtMjBZMVZsWlJYejFONnE0cFNEZ0NSVHZ5eGswQ002TXZISE5BK25ORTJPV0E2eEoyOTZobHpzZ3NyODNyZHM4UmFleWhrL2QzRmc3Vm5wWi9zc2pza1BPL21wWThzeVdrMjIyNjRWNm1WWkJCeFZRQnpETmFDK3J3KzFXb1VXRE9nL0Viei9qbkZ6d0V3eTZxbjUraFgyR2R6QzhtKzNUeXVaM0xJOHg4N3o5T0orZHdkbXpMQTdBZEpLVFVDTVpKekZjQ2Z4SHNPeWRuUXQ1TFdlcDZ3bHZTMVpmU1huemdvZjNld2xXRktNZElxMVlmVXYxQjBueW9IZmNiRjZyWGxPWHRWbFFRaUZFTmVzNzViQVhUM3ZPZlRERGFsR3Mza2pxanhRV25BMmE4Uy9pcVloNzZHTVNtSDU3SXdiejJVOENzV3YrSnl2MXVFV2JxWHp2WmVnLzhpdmFjRGtpRFhhQTVSbUU1cVFHOFVXMmlWS1crWmF5WTdON1pKRG9hOEIyQ1N0NXV5NTBHQ09qL0ZJRGR6U0FoOFJncVIvMFFPS29nWXlGMG1xQWVpdGdxUkpIYnFOUUxDNUlOZUZmZzQwV1l3aHVyVmxGR3ZDZWgrOWh1U2YzR1hCaFA5cEZXaGtRYTlDTEpSc3FmYnl0UlRKbkdsK0d1WkpwemFab1hPd1pMZDJHMXFYTFpHb2swRThvMjVDc21TcWp4Unp1ZDJHOGtwZk9RQ1NTRytvWG9Yc3d5bk1nRzMxZ1NySTZ6Lzk3MGcydVZNUmk4bGRGU2x5ZzhWbE82ZHZjQk9XL2FxT0FKTFVlV3NqNWFaSVp2S3FPa2VqeVB1dzE5TUNWSXBDU1QwcnlDcENod1U3SE8xclBaQndxcWJiRVNxazR3TUxTaWpHQUlFWU9uM2E2YXZkcWZBcDdFYVpjczliSTRpMGZ6bi9EVUdnbDVzUmFUQkdhRzBTUlBzbE5Pd3JNOTZ6RTVRU1pCcGMvd3Z1eHFlUSt5WEdNUEE2SENkR3J4RzEyeklIZktFYUF5MEhwcXBTQTcrTyszcnhPZUFPOUhEbEczWitmMXJPOGFwWkhwSzRjZ1h0K0ZCTUtleVMrdW9sOWUyZlQ1ak9OYnlxejhNTHlWSFpoVXFvUDhPenlsZWJUazBWM2JmcGo4OHhaQkpEQzdITURoNk9MTzVxZ1pJdGExMWkxdm0rakhJNUVoT25TVm84UkRXUnZMZEtxY2l6anNwc2J1cFpPMTlrQTdoSGk0UjBRSnoxVG9Ia0Z5N0l4bGhyOWRtY1VzbGh2UHdTeWFGdjB3ZDRaMHVzWHJST3g5STJ2bUJCRmg4UWxYT3RZdmw3V0hrOXhuY0Z5SzJZOWdCaEYyQ21qTlB3MTc5TFRQOS9YelJXaUxBdjk1MzZWaTBvaTdOTk16Z1k0K1BXMmZMQS9QRW9BdEZUZk96MFY1YzVMZ09EUFcwdE1BcWdGYzdBSDRKa2tqejNpdWZ5aWNBSUtFYmV5STkvbTBPM2ZqMkdaL3lMRk9uRnpsakhNVmxzMHZHQ1A2bE9vVkpTc3pxMDkxc0hXNVQydmsyQlJPUjFKRkFtblphSHFQZVMrL2tCaG1wQW9mcDZTazB4b3pxSW03M2ppTWxRZXFEOEZyc1Mrb2Qvb1RnPT0=")
	// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错 可以自己传入初始化向量,如果不传就使用默认的初始化向量,16字节
	newplaintext, err := cs.CipherSuiteInterface.SymmetricKeyDecrypt(cryptText, []byte("0123456789abcdef"))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("AES的CBC模式解密完：", string(newplaintext))

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
	privateKey := []byte(testRsaPri)
	publicKey := []byte(testRsaPub)

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
	testRsaPri = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA89pZATcqBotIMQzDmQK+gPas7Se8FOOb9+NkDUvolEatIJ5R
Jh42ek0uJVSnnkareW1FsSQgQWlgQjyyaFlHmvD2FE7TK9UwkgXtqQpn18oIfaET
pbgBbtC663jHBzTQnrCrc4rx4DwO65FYv8ph98X2Wh3eanUBCl5rsWugoMAqPN1Q
wIIOFopNos9IyEnIcf5AXIaU3e03yie9kDr1fo8XCUGEfdJEWwJozPiPlWYH8y9b
qyRsPwOxKk7KSvxGdeaxrFgHAuu+vlUh7SeE9HFRySCOpS0Tg/WWEBEuf4p/g6tn
pDebEm40Ilyx2ujXFJ0NoT1cnHASLtNxI6XMKwIDAQABAoIBAQDJoewikyiOzLBe
zn0Vki1PmaiXWFmutB2NNVrPm8qugFo7NG1JJYZKTnMvrvYCa9Dx0KbluEdrjuRn
IKUsn1YUCdaQKDV4cwl8VKaVNeNzjLzElGIYjzOwG6vTdMStcsBl1xONsIAbt81m
f4Jw47lqFSiEj1oPkLvRhQ1rYOEqyN1ySy4uGRbs5Jg1888dtoEuuqxfL1V5VwmN
9/v77rsySIwc5GTsKRlApac04tfIMX7FrD5kKeXzrDizQTP+g5grxl2jry9lKHpf
qwSGkJz0sXzgvIbc1lcGVvWFL1S7NgtAnk61zUzut9EpAH+l1c2SUu7si0LiW9j6
BTmxV3NxAoGBAPlOkYTemtGHhMrGAmNfP/ULZdIp98+2qo3ya6Qvvb9jE0SVr9h0
EZgfbeXB52bFahJuz9/9n3XpEWnh6W44A7ESHbMTQt5t4OHemG3NL82dWEsbb8zB
x97tCn3m4ZtGAqTwtYPgucMBGU9HSwFWtUrk5inRRmekHYscqW40dpwNAoGBAPpm
S5FCcHoRGQHTSTEtkEKx9vbd7mSDe3PcNLmZu4ulm9JGSmoO9WC5PzHrCYp+LOMM
uaNNQmYcQ5tr/OdLk84vpbBxIbD02SElcIzGYi5hwNaYaAlDZKh4DQ+7fN8cRA0S
X0ALR3weC5+bEX9bDCRNatNf+U2C4JgurY0aSCMXAoGBAKOvX0HCuhl6Bcjwyt6d
yitEaXzcSzVYtJBwKxZotgdzsFHmicbvJiIf+JLShfDnCubBVMC3D7xl4yYGyrGw
G1RmFZPewJezwuPpt2DYSFuSxEbD49qnHGiUb8AMF/JPvCq5VCQbJzwOe6SepXNi
j7N1qFyqZ7Rif3c3wVJ3Jaz9AoGBAKD8mcMHezcPvQsuY1VJ3QD0WDp5jyZyXjGs
Nv3I+AodbGQxqvArM9l+4EFgwl6XJpbHfKagKntp2pGXSR8PuTSL77PT2HxjvyGP
Z6Aqf78gPBH8JI8oFBQ4MvWVbgAntRzOXgzX85q52nFACmzeBZ1lZLQHdUo/RdSx
1gTtC8n7AoGAGa8G+w6do6B+HOoApB3AQTgWiBa+tCqT+U3+eKAuB/Ymg47Vhd9a
CKsIToIEn3ZMhTl8k/rDSe3qckVHdr7aJHu6q5YjbNUDrpiQMCJUxjMbydGQYfeS
1MVKwjO3LHd4SdetB7Xwns4qKET7r989iQt9hDIVCSQf/4KbjwQ8CSc=
-----END RSA PRIVATE KEY-----
`
	testRsaPub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA89pZATcqBotIMQzDmQK+
gPas7Se8FOOb9+NkDUvolEatIJ5RJh42ek0uJVSnnkareW1FsSQgQWlgQjyyaFlH
mvD2FE7TK9UwkgXtqQpn18oIfaETpbgBbtC663jHBzTQnrCrc4rx4DwO65FYv8ph
98X2Wh3eanUBCl5rsWugoMAqPN1QwIIOFopNos9IyEnIcf5AXIaU3e03yie9kDr1
fo8XCUGEfdJEWwJozPiPlWYH8y9bqyRsPwOxKk7KSvxGdeaxrFgHAuu+vlUh7SeE
9HFRySCOpS0Tg/WWEBEuf4p/g6tnpDebEm40Ilyx2ujXFJ0NoT1cnHASLtNxI6XM
KwIDAQAB
-----END PUBLIC KEY-----
`
)

const (
	PRIVATE_KEY2 = `-----BEGIN  WUMAN RSA PRIVATE KEY -----
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
	PUBLIC_KEY2 = `-----BEGIN  WUMAN  RSA PUBLIC KEY -----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDuxlkVpBB4zPoNzBh9F
0OLeR8kk/8/ewryuVlj2/SM5gLaNI8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhh
LreB566m+H4TrobaRfrhe2ZQG/E28XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzT
M1p1XlA1mrJPc7GlDKCRcUiPDn+nZ67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8
NLGMSBW8/zOxNdeC3S+8ni6HjXsjWft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7
A0+CrDSvVGp9QPuQhdCyf6INduHpINzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJ
nwIDAQAB
-----END  WUMAN  RSA PUBLIC KEY -----`
	CERT2 = ``
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
LjG+NLJBk1dQn4EEE44iwhEGgj1jdO4lCziuJoAWTsFwHpTiJDhdW78ZNsgHejC+·
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

func TestRSASign(t *testing.T) {
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)
	msg := []byte("RSA数字签名测试")
	cs := NewCipherSuiteModel(100)
	signmsg, err := cs.CipherSuiteInterface.AsymmetricKeySign(msg, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("RSA数字签名的消息为：", hex.EncodeToString(signmsg))

	// 验证数字签名正不正确
	result, err := cs.CipherSuiteInterface.AsymmetricKeyVerifySign(msg, signmsg, publicKey)
	if result { // 如果result返回的是 true 那么就是本人签名，否则不是，只有私钥加密，相对的公钥验证才可以认为是本人
		fmt.Println("RSA数字签名正确，是本人")
	} else {
		fmt.Println("RSA数字签名错误，不是本人")
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

func TestECCEncrypt(t *testing.T) {
	plainText := []byte("窗前明月光，疑是地上霜,ECC加密解密 就诶将阿里金融离开家啊饿疯了快捷洒鲁昆吉里卡家里发大水sfdafsadf   s04=234=32=-4032-==+窗前明月光，疑是地上霜,ECC加密解密")

	// 这里传入的私钥和公钥是要用GetECCKey里面得到的私钥和公钥，如果自己封装的话，
	// 获取密钥时传入的第一个参数是要用这条曲线elliptic.P256()，如果用别的会报无效公钥错误，
	// 例如用P521()这条曲线
	privateKey := []byte(eccprivateKey)
	publicKey := []byte(eccpublicKey)
	var cs CipherSuiteInterface
	cs = cipherSuites.NewECDSA_AES256_CBC_SHA256Model()
	cryptText, _ := cs.AsymmetricKeyEncrypt(plainText, publicKey)
	fmt.Println("ECC传入公钥加密的密文为：", hex.EncodeToString(cryptText))

	msg, err := cs.AsymmetricKeyDecrypt(cryptText, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("ECC传入私钥解密后的明文为：", string(msg))
}

func MyEccEncrypt(plainText, key []byte) (cryptText []byte, err error) {
	block, _ := pem.Decode(key)
	var publicKey interface{}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		publicKey = key
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {

	}
	fmt.Println(reflect.TypeOf(ecdsaPublicKey))
	publicKeyParse := goEncrypt.ImportECDSAPublic(ecdsaPublicKey)
	crypttext, err := goEncrypt.Encrypt(rand.Reader, publicKeyParse, plainText, nil, nil)

	//defer func() {
	//	if err := recover(); err != nil {
	//		switch err.(type) {
	//		case runtime.Error:
	//			log.Println("runtime err:", err, "Check that the key is correct")
	//		default:
	//			log.Println("error:", err)
	//		}
	//	}
	//}()
	//tempPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	//if err != nil {
	//	return nil, err
	//}
	//// Decode to get the private key in the ecdsa package
	//publicKey1 := tempPublicKey.(*ecdsa.PublicKey)
	// Convert to the public key in the ecies package in the ethereum packag
	return crypttext, err

}
func MyEccDecrypt(cryptText, key []byte) (msg []byte, err error) {
	block, _ := pem.Decode(key)

	tempPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	//if err != nil {
	//
	//}
	//ecdsaPriKey, ok := tempPrivateKey.(*ecdsa.PrivateKey)
	//if !ok {
	//
	//}

	//tempPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	//tempPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	//if err!=nil{
	//	return nil,err
	//}
	// Decode to get the private key in the ecdsa package
	// Convert to the private key in the ecies package in the ethereum package
	ecdsaPriKey := tempPrivateKey.(*ecdsa.PrivateKey)
	privateKey := goEncrypt.ImportECDSA(ecdsaPriKey)

	plainText, err := privateKey.Decrypt(cryptText, nil, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
func TestECCSign(t *testing.T) {
	privateKey := []byte(eccprivateKey)
	publicKey := []byte(eccpublicKey)
	msg := []byte("数字签名测试")
	//cs := NewCipherSuiteModel(cipherSuites.CIPHER_SUITE_MAP["ECDSA_AES256_CBC_SHA256"])
	rtext, stext, err := goEncrypt.EccSign(msg, privateKey)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("数字签名的消息为：", hex.EncodeToString(rtext)+hex.EncodeToString(stext))

	// 验证数字签名正不正确
	result := goEncrypt.EccVerifySign(msg, publicKey, rtext, stext)
	if result { // 如果result返回的是true那么就是本人签名，否则不是，只有私钥加密，相对的公钥验证才可以认为是本人
		fmt.Println("数字签名正确，是本人")
	} else {
		fmt.Println("数字签名错误，不是本人")
	}
}

func TestECCKey(t *testing.T) {
	hash := goEncrypt.Sha256Hex([]byte(eccpublicKey))
	fmt.Println(hash)
}

const (
	eccprivateKey = `-----BEGIN WUMAN ECC PRIVATE KEY-----
MHcCAQEEIKozbXD9G6bGPJ26cCAfEdLrqAe697F8SiLRMdqxzNQ5oAoGCCqGSM49
AwEHoUQDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1vFooGpsKCbLvrdUW4peVIwKEW
+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PRIVATE KEY-----`
	eccpublicKey = `-----BEGIN WUMAN ECC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1v
FooGpsKCbLvrdUW4peVIwKEW+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PUBLIC KEY-----`
)

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
const (
	pemCert = `-----BEGIN CERTIFICATE-----
MIICeDCCAh+gAwIBAgIQOhVMvntDXluxaJi7Nfv7rzAKBggqhkjOPQQDAjCBhjEL
MAkGA1UEBhMCY24xEDAOBgNVBAgTB2ppYW5nc3UxEDAOBgNVBAcTB25hbmppbmcx
FDASBgNVBAkTC2d1eWFuZ3Rhc2hhMQ8wDQYDVQQREwYxMjM0NTYxDjAMBgNVBAoT
BWNpMTIzMQswCQYDVQQLEwJjaTEPMA0GA1UEAxMGY2kuY29tMB4XDTIwMDQyMTA0
MTYwMFoXDTMwMDQxOTA0MTYwMFowgYYxCzAJBgNVBAYTAmNuMRAwDgYDVQQIEwdq
aWFuZ3N1MRAwDgYDVQQHEwduYW5qaW5nMRQwEgYDVQQJEwtndXlhbmd0YXNoYTEP
MA0GA1UEERMGMTIzNDU2MQ4wDAYDVQQKEwVjaTEyMzELMAkGA1UECxMCY2kxDzAN
BgNVBAMTBmNpLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLrp8iUDPPud
I6rvdYVQiC6eY5eovRuTraeIOYkLKSorklvGiHjLlYq4XNvaYfZ6/2sFwf6iD3Mi
ufHa70nLpt2jbTBrMA4GA1UdDwEB/wQEAwIBpjAdBgNVHSUEFjAUBggrBgEFBQcD
AgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zApBgNVHQ4EIgQgzUFDghYBvHf4
KN6eVBci+BueR8bzVlrxu5fYBcEYtYEwCgYIKoZIzj0EAwIDRwAwRAIgeHQ7lm9f
Uz2sc98rkshBW5AucgxWzLNSgSBUsq79XQkCIDt1GhKT2EOGWqQkyRRkaTflDtt6
ktXMBrWDJP/HYbWt
-----END CERTIFICATE-----`
	pemPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9/UZdUOC23V0PQQi
wRy5EsXM3IEc1Wg2IPX3BV3S1qehRANCAAS66fIlAzz7nSOq73WFUIgunmOXqL0b
k62niDmJCykqK5Jbxoh4y5WKuFzb2mH2ev9rBcH+og9zIrnx2u9Jy6bd
-----END PRIVATE KEY-----`
	pemPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuunyJQM8+50jqu91hVCILp5jl6i9
G5Otp4g5iQspKiuSW8aIeMuVirhc29ph9nr/awXB/qIPcyK58drvScum3Q==
-----END PUBLIC KEY-----`
)

func TestByteToString(t *testing.T) {
	tmp := []byte("alkjflkajsfljalkfjlkasjf+_=-=248384   __// ")
	fmt.Println(string(tmp))

}
