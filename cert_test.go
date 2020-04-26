package gosdk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"
)

func TestWriteFile(t *testing.T) {
	tlsConfigMap := map[string]TlsConfig{}
	c1 := TlsConfig{
		SessionId:             "123456",
		IsClient:              false,
		HandshakeState:        nil,
		IsEncryptRequired:     false,
		IsCertRequired:        false,
		State:                 0,
		CipherSuites:          nil,
		CipherSuite:           0,
		Time:                  time.Time{},
		Timeout:               0,
		Randoms:               nil,
		PrivateKey:            nil,
		PublicKey:             nil,
		SymmetricKey:          nil,
		SymmetricKeyCreatedAt: time.Time{},
		SymmetricKeyExpiresAt: time.Time{},
		Cert:                  nil,
		CertChain:             nil,
		CertLoader:            nil,
		HandshakeMsgs:         nil,
		Logs:                  nil,
	}
	tlsConfigMap[c1.SessionId] = c1
	c2 := TlsConfig{
		SessionId:             "asdfgh",
		IsClient:              false,
		HandshakeState:        nil,
		IsEncryptRequired:     false,
		IsCertRequired:        false,
		State:                 0,
		CipherSuites:          nil,
		CipherSuite:           0,
		Time:                  time.Time{},
		Timeout:               0,
		Randoms:               nil,
		PrivateKey:            nil,
		PublicKey:             nil,
		SymmetricKey:          nil,
		SymmetricKeyCreatedAt: time.Time{},
		SymmetricKeyExpiresAt: time.Time{},
		IsReuse:               true,
		Cert:                  nil,
		CertChain:             nil,
		CertLoader:            nil,
		HandshakeMsgs:         nil,
		Logs:                  nil,
	}
	tlsConfigMap[c2.SessionId] = c2
	cMarshal, err := json.Marshal(tlsConfigMap)
	if err != nil {
		return
	}
	file, err := os.OpenFile("test.txt", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	n, err := file.Write(cMarshal)
	if err != nil {

	}
	fmt.Println(n)

}

func TestReadFile(t *testing.T) {
	data, err := ioutil.ReadFile("test.txt")
	if err != nil {

	}
	var cList map[string]TlsConfig
	err = json.Unmarshal(data, &cList)
	if err != nil {

	}
}
