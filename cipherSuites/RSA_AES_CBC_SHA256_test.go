package cipherSuites

import (
	"encoding/hex"
	"fmt"
	"github.com/wumansgy/goEncrypt"
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
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)
	msg := []byte("RSA数字签名测试JLKSDJFLJSLKDFJLKSDFJJ")
	signmsg, err := goEncrypt.RsaSign(msg, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("RSA数字签名的消息为：", hex.EncodeToString(signmsg))

}

func TestRSA_AES_CBC_SHA256_AsymmetricKeySign(t *testing.T) {
	type args struct {
		data       []byte
		privateKey []byte
	}
	tests := []struct {
		name     string
		args     args
		wantSign []byte
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RSA_AES_CBC_SHA256{}
			gotSign, err := c.AsymmetricKeySign(tt.args.data, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("AsymmetricKeySign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSign, tt.wantSign) {
				t.Errorf("AsymmetricKeySign() gotSign = %v, want %v", gotSign, tt.wantSign)
			}
		})
	}
}

func TestRSA_AES_CBC_SHA256_AsymmetricKeyVerify(t *testing.T) {
	type args struct {
		data      []byte
		sign      []byte
		publicKey []byte
	}
	tests := []struct {
		name     string
		args     args
		wantFlag bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RSA_AES_CBC_SHA256{}
			if gotFlag := c.AsymmetricKeyVerify(tt.args.data, tt.args.sign, tt.args.publicKey); gotFlag != tt.wantFlag {
				t.Errorf("AsymmetricKeyVerify() = %v, want %v", gotFlag, tt.wantFlag)
			}
		})
	}
}

func TestRSA_AES_CBC_SHA256_CipherSuiteKey(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RSA_AES_CBC_SHA256{}
			if got := c.CipherSuiteKey(); got != tt.want {
				t.Errorf("CipherSuiteKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSA_AES_CBC_SHA256_CreateMAC(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantMAC []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RSA_AES_CBC_SHA256{}
			if gotMAC := c.CreateMAC(tt.args.data); !reflect.DeepEqual(gotMAC, tt.wantMAC) {
				t.Errorf("CreateMAC() = %v, want %v", gotMAC, tt.wantMAC)
			}
		})
	}
}

func TestRSA_AES_CBC_SHA256_CreateSymmetricKey(t *testing.T) {
	tests := []struct {
		name             string
		wantSymmetricKey []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RSA_AES_CBC_SHA256{}
			if gotSymmetricKey := c.CreateSymmetricKey(); !reflect.DeepEqual(gotSymmetricKey, tt.wantSymmetricKey) {
				t.Errorf("CreateSymmetricKey() = %v, want %v", gotSymmetricKey, tt.wantSymmetricKey)
			}
		})
	}
}

func TestRSA_AES_CBC_SHA256_SymmetricKeyDecrypt(t *testing.T) {
	type args struct {
		cipherText   []byte
		symmetricKey []byte
	}
	tests := []struct {
		name          string
		args          args
		wantPlainText []byte
		wantErr       bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RSA_AES_CBC_SHA256{}
			gotPlainText, err := c.SymmetricKeyDecrypt(tt.args.cipherText, tt.args.symmetricKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("SymmetricKeyDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPlainText, tt.wantPlainText) {
				t.Errorf("SymmetricKeyDecrypt() gotPlainText = %v, want %v", gotPlainText, tt.wantPlainText)
			}
		})
	}
}

func TestRSA_AES_CBC_SHA256_SymmetricKeyEncrypt(t *testing.T) {
	type args struct {
		plainText    []byte
		symmetricKey []byte
	}
	tests := []struct {
		name           string
		args           args
		wantCipherText []byte
		wantErr        bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &RSA_AES_CBC_SHA256{}
			gotCipherText, err := c.SymmetricKeyEncrypt(tt.args.plainText, tt.args.symmetricKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("SymmetricKeyEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCipherText, tt.wantCipherText) {
				t.Errorf("SymmetricKeyEncrypt() gotCipherText = %v, want %v", gotCipherText, tt.wantCipherText)
			}
		})
	}
}
