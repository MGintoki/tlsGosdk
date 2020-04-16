package gosdk

import (
	"fmt"
	"github.com/pretty66/gosdk/cipherSuites"
	"reflect"
	"testing"
)

func TestSha(t *testing.T) {
	//hash := goEncrypt.Sha512Hex([]byte("test"))
	//fmt.Println(hash)
}

func TestStruct(t *testing.T) {
	cs := &CipherSuite{}
	cs_rsa := cipherSuites.NewRSA_AES_CBC_SHA256Model()
	cs.cipherSuiteInterface = cs_rsa
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

func TestPEM(t *testing.T) {
	//privateKey := []byte(pemPrivateKey)
	//publicKey := []byte(pemPublicKey)
	//
	//plaintext := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程")
	//// 直接传入明文和公钥加密得到密文
	//crypttext, err := goEncrypt.RsaEncrypt(plaintext, publicKey)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println("密文", hex.EncodeToString(crypttext))
	//// 解密操作，直接传入密文和私钥解密操作，得到明文
	//plaintext, err = goEncrypt.RsaDecrypt(crypttext, privateKey)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println("明文：", string(plaintext))
}

const (
	PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzunGAeDoQFoqz6SH2Aj1wRWPTIc2wyjC4K/OPBSltWNJAtWu
xAFarCyPSaFoG3AxcD+Nb+/ZLxd8e/x8chiib2CjXOa14DRU590j+nsYH5o4/+hc
t/gKJb8JSppFlIsQgx+IP4MeeSLMDMiIo+15WxGU9xNMLrPvF9szQmRX5uRFrjRG
ivBDHGgAFETqUD/gpXYaK4ILJrndx4LDZuBSPcOjGCH1M5vBZYAxKkkQNSTOIBEN
Q/gxcud6GPkYEx1KMix90zCnW9Chqqb597Syg1KBemfdceFBbFa3R//1CZFwBvsV
BpMIhz/O9HFiJl9046yUEM1jm81Abc2AoejjgQIDAQABAoIBAE+SIT6JsmdFBZ+y
ozcWQwQM+X2xpgKpQ0BK+6GpQwydcO9xI3NnHeqGfFgRhUq/+5MyLX81mqz8eDfq
IiVyic0ROeG5K4pcNaaxKWvjOKS2l2L6heWNssFPVRBmgYmdbS0vzCK4lth45EWq
PLnl0jyOZ14ZArwXIERpXK4UjqVQxNm46d5JP6ooqimg5IobJsYeQDGmQsTA2oXI
9Tfan59wu0Lk0h0w6xz7TDxvO+hIsuTS5mWTBRQ8NccXrsM+JUh5HoOnS9ReAhd2
gR97kjqqhQ3AZVO/gPSuydaZWAKuJJtdbW2N91Yy80uMU9JrZDJfCFH/XtMwOQuS
6Dwcys0CgYEA6sjtXdWnPL6FEPbwpKDjyDz+AU/AkPxw/fdWhwMW/zcoTq/vFJP9
Uu4mHyVRh10OVsxDvmK98zPvQJNw+1vtBeiUcE21ZX1qHqwzu5kT1jEqQ+Z0oFG8
ukK0oq7IGTxoVuUlSdEWxYTICFbTlcZy1mVwujp9G2iDnhJge8qfkR8CgYEA4Zwd
YQrSD3vrPVhF0Pw5j50vuLqJOxOgh+dL7WWLl5vWY3l0neimr71NcT+2mBM6lZ82
qOF6Kv6wnTG81Mfg1vniQO5RtUgsHyFtNtpr0ivQqk0gmflXuZKQG0Sf4CYJi8Zi
+atrnVvusfCocI2kIPgHwZIO5l4Z4Z7H5nMP118CgYBNbK06QHbCBWIEUirRX20+
Xz60WAR8y4LHfYU/SLmQuDPGnyYMdzEW5AoWQ0w7g2hzHzFH23Agf4Pqm7Sqb4oe
ZLBuyHGFYnJYYxk8SCLOg7AYbCsRo2LFWbIP4+uAxvbxkOdXDGiiAkOk3F0yCxtb
sGAYSalwHGsq+YxvxkYQqQKBgQCpA/R6g8m0segcj+nV028n6OEcahpuuJh119Bo
6770+FlXMmEr/2QImi/PHKUlLpqgBqPDRw/n79/OE7ncSlVll9RpQmDSB1yOgdM4
2c8Wp55uRtOaplKTAnqVAwcmvDhAj4IMeuBnBb0/bwQxNdt0m3vsBwjEilCnVvV4
7lA6zwKBgQCCaZ56vRiaM2lx9C9r8yOPTZ+9zPFv8vkUXB0g38uxcoxdl0grwZdJ
gsHErP5e9q2YdY4qMB3jkrX3huPYJULgMTtaXZBDk+3ziQrVDpLR6XI65YU9f3zq
TI91hxIpO7HF8wet7b4guGGZjWOx2/YQEhzfOK02IRAM09dCRKeDvA==
-----END RSA PRIVATE KEY-----
`
	PUBLIC_KEY = `-----BEGIN  WUMAN  RSA PUBLIC KEY -----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDuxlkVpBB4zPoNzBh9F
0OLeR8kk/8/ewryuVlj2/SM5gLaNI8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhh
LreB566m+H4TrobaRfrhe2ZQG/E28XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzT
M1p1XlA1mrJPc7GlDKCRcUiPDn+nZ67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8
NLGMSBW8/zOxNdeC3S+8ni6HjXsjWft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7
A0+CrDSvVGp9QPuQhdCyf6INduHpINzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJ
nwIDAQAB
-----END  WUMAN  RSA PUBLIC KEY -----`
	CERT = `-----BEGIN CERTIFICATE-----
MIIDyjCCArKgAwIBAgIQcoa9FyUaQI6ZQhd8cv4mMjANBgkqhkiG9w0BAQsFADBe
MQswCQYDVQQGEwJDTjEOMAwGA1UEChMFTXlTU0wxKzApBgNVBAsTIk15U1NMIFRl
c3QgUlNBIC0gRm9yIHRlc3QgdXNlIG9ubHkxEjAQBgNVBAMTCU15U1NMLmNvbTAe
Fw0yMDA0MTYwNzQ5MjRaFw0yMTA0MTYwNzQ5MjRaMB8xCzAJBgNVBAYTAkNOMRAw
DgYDVQQDEwdzZXJ2ZXIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
zunGAeDoQFoqz6SH2Aj1wRWPTIc2wyjC4K/OPBSltWNJAtWuxAFarCyPSaFoG3Ax
cD+Nb+/ZLxd8e/x8chiib2CjXOa14DRU590j+nsYH5o4/+hct/gKJb8JSppFlIsQ
gx+IP4MeeSLMDMiIo+15WxGU9xNMLrPvF9szQmRX5uRFrjRGivBDHGgAFETqUD/g
pXYaK4ILJrndx4LDZuBSPcOjGCH1M5vBZYAxKkkQNSTOIBENQ/gxcud6GPkYEx1K
Mix90zCnW9Chqqb597Syg1KBemfdceFBbFa3R//1CZFwBvsVBpMIhz/O9HFiJl90
46yUEM1jm81Abc2AoejjgQIDAQABo4HCMIG/MA4GA1UdDwEB/wQEAwIHgDATBgNV
HSUEDDAKBggrBgEFBQcDAjAfBgNVHSMEGDAWgBQogSYF0TQaP8FzD7uTzxUcPwO/
fzBjBggrBgEFBQcBAQRXMFUwIQYIKwYBBQUHMAGGFWh0dHA6Ly9vY3NwLm15c3Ns
LmNvbTAwBggrBgEFBQcwAoYkaHR0cDovL2NhLm15c3NsLmNvbS9teXNzbHRlc3Ry
c2EuY3J0MBIGA1UdEQQLMAmCB3NlcnZlcjEwDQYJKoZIhvcNAQELBQADggEBAKIa
PLwR7q4yHykiBm3qYoKldTdiDpDOcyxPgDoOA5kcAjvSTChgYnlJn3/gTT2TRjy0
lVa/e04EAr7YwLbBCHgcgMtbz8G+gpmCj5yVm16p1JWsXr/YADNYD/CkV0aiBFJ5
epilqJvdcxzYkPEoeL0TzZZuFQVtv4QfmNLqhcAzEXb99mJh7Py1WJ0WwXj2oAsD
Ir24Pd/buEQQZEwkZcDQvUeUkdUrJxfJI8w1c9lNYAug5IggLsi1dIGTp90wF/ox
sw+KXUAYY4W+pA7GnCDBKGmhHsVWN3OUPXAPo0KV/nlC92mYLFPqY2OsSAH3sh3s
Wn14/pV2YNwhNrelAdM=
-----END CERTIFICATE-----
`
	CERT_CHAIN = `-----BEGIN CERTIFICATE-----
MIIDyjCCArKgAwIBAgIQcoa9FyUaQI6ZQhd8cv4mMjANBgkqhkiG9w0BAQsFADBe
MQswCQYDVQQGEwJDTjEOMAwGA1UEChMFTXlTU0wxKzApBgNVBAsTIk15U1NMIFRl
c3QgUlNBIC0gRm9yIHRlc3QgdXNlIG9ubHkxEjAQBgNVBAMTCU15U1NMLmNvbTAe
Fw0yMDA0MTYwNzQ5MjRaFw0yMTA0MTYwNzQ5MjRaMB8xCzAJBgNVBAYTAkNOMRAw
DgYDVQQDEwdzZXJ2ZXIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
zunGAeDoQFoqz6SH2Aj1wRWPTIc2wyjC4K/OPBSltWNJAtWuxAFarCyPSaFoG3Ax
cD+Nb+/ZLxd8e/x8chiib2CjXOa14DRU590j+nsYH5o4/+hct/gKJb8JSppFlIsQ
gx+IP4MeeSLMDMiIo+15WxGU9xNMLrPvF9szQmRX5uRFrjRGivBDHGgAFETqUD/g
pXYaK4ILJrndx4LDZuBSPcOjGCH1M5vBZYAxKkkQNSTOIBENQ/gxcud6GPkYEx1K
Mix90zCnW9Chqqb597Syg1KBemfdceFBbFa3R//1CZFwBvsVBpMIhz/O9HFiJl90
46yUEM1jm81Abc2AoejjgQIDAQABo4HCMIG/MA4GA1UdDwEB/wQEAwIHgDATBgNV
HSUEDDAKBggrBgEFBQcDAjAfBgNVHSMEGDAWgBQogSYF0TQaP8FzD7uTzxUcPwO/
fzBjBggrBgEFBQcBAQRXMFUwIQYIKwYBBQUHMAGGFWh0dHA6Ly9vY3NwLm15c3Ns
LmNvbTAwBggrBgEFBQcwAoYkaHR0cDovL2NhLm15c3NsLmNvbS9teXNzbHRlc3Ry
c2EuY3J0MBIGA1UdEQQLMAmCB3NlcnZlcjEwDQYJKoZIhvcNAQELBQADggEBAKIa
PLwR7q4yHykiBm3qYoKldTdiDpDOcyxPgDoOA5kcAjvSTChgYnlJn3/gTT2TRjy0
lVa/e04EAr7YwLbBCHgcgMtbz8G+gpmCj5yVm16p1JWsXr/YADNYD/CkV0aiBFJ5
epilqJvdcxzYkPEoeL0TzZZuFQVtv4QfmNLqhcAzEXb99mJh7Py1WJ0WwXj2oAsD
Ir24Pd/buEQQZEwkZcDQvUeUkdUrJxfJI8w1c9lNYAug5IggLsi1dIGTp90wF/ox
sw+KXUAYY4W+pA7GnCDBKGmhHsVWN3OUPXAPo0KV/nlC92mYLFPqY2OsSAH3sh3s
Wn14/pV2YNwhNrelAdM=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIQSEIWDPfWTDKZcWNyL2O+fjANBgkqhkiG9w0BAQsFADBf
MQswCQYDVQQGEwJDTjEOMAwGA1UEChMFTXlTU0wxLDAqBgNVBAsTI015U1NMIFRl
c3QgUm9vdCAtIEZvciB0ZXN0IHVzZSBvbmx5MRIwEAYDVQQDEwlNeVNTTC5jb20w
HhcNMTcxMTE2MDUzNTM1WhcNMjcxMTE2MDUzNTM1WjBeMQswCQYDVQQGEwJDTjEO
MAwGA1UEChMFTXlTU0wxKzApBgNVBAsTIk15U1NMIFRlc3QgUlNBIC0gRm9yIHRl
c3QgdXNlIG9ubHkxEjAQBgNVBAMTCU15U1NMLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMBOtZk0uzdG4dcIIdcAdSSYDbua0Bdd6N6s4hZaCOup
q7G7lwXkCyViTYAFa3wZ0BMQ4Bl9Q4j82R5IaoqG7WRIklwYnQh4gZ14uRde6Mr8
yzvPRbAXKVoVh4NPqpE6jWMTP38mh94bKc+ITAE5QBRhCTQ0ah2Hq846ZiDAj6sY
hMJuhUWegVGd0vh0rvtzvYNx7NGyxzoj6MxkDiYfFiuBhF2R9Tmq2UW9KCZkEBVL
Q/YKQuvZZKFqR7WUU8GpCwzUm1FZbKtaCyRRvzLa5otghU2teKS5SKVI+Tpxvasp
fu4eXBvveMgyWwDpKlzLCLgvoC9YNpbmdiVxNNkjwNsCAwEAAaN0MHIwDgYDVR0P
AQH/BAQDAgGGMA8GA1UdJQQIMAYGBFUdJQAwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
HSMEGDAWgBSa8Z+5JRISiexzGLmXvMX4oAp+UzAdBgNVHQ4EFgQUKIEmBdE0Gj/B
cw+7k88VHD8Dv38wDQYJKoZIhvcNAQELBQADggEBAEl01ufit9rUeL5kZ31ox2vq
648azH/r/GR1S+mXci0Mg6RrDdLzUO7VSf0JULJf98oEPr9fpIZuRTyWcxiP4yh0
wVd35OIQBTToLrMOWYWuApU4/YLKvg4A86h577kuYeSsWyf5kk0ngXsL1AFMqjOk
Tc7p8PuW68S5/88Pe+Bq3sAaG3U5rousiTIpoN/osq+GyXisgv5jd2M4YBtl/NlD
ppZs5LAOjct+Aaofhc5rNysonKjkd44K2cgBkbpOMj0dbVNKyL2/2I0zyY1FU2Mk
URUHyMW5Qd5Q9g6Y4sDOIm6It9TF7EjpwMs42R30agcRYzuUsN72ZFBYFJwnBX8=
-----END CERTIFICATE-----`
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
