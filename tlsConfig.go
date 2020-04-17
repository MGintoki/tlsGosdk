package gosdk

import (
	"time"
)

type TlsConfig struct {
	SessionId      string                `json:"sessionId"`
	IsClient       bool                  `json:"isClient"`
	HandshakeState StateMachineInterface `json:"handshakeState"`
	IsCertRequired bool                  `json:"isCertRequired"`
	ServerName     string                `json:"serverName"`
	State          int                   `json:"state"`
	CipherSuites   []int                 `json:"cipherSuites"`
	CipherSuite    int                   `json:"cipherSuite"`
	Time           time.Duration         `json:"time"`
	Timeout        time.Duration         `json:"timeout"`
	Randoms        []string              `json:"randoms"`
	Keypair        keypair               `json:"keypair"`
	SymmetricKey   SymmetricKey          `json:"symmetricKey"`
	Cert           string                `json:"cert"`
	CertChain      []string              `json:"certChain"`
	HandshakeMsgs  map[int]Handshake     `json:"handshakeMsgs"`
	Logs           []string              `json:"logs"`
}

const (
	TLS_STATE_ACTIVING = 1
	TLS_STATE_BROKE    = 0
)

//根据sessionId实例化一个tlsConfig
func ReuseSession(sessionId, filepath string) *TlsConfig {
	return nil
}

//传入连个节点数据，判断是否需要开启加密通信
func GetNeedCrypt(testFlag bool) bool {
	return testFlag
}

func GetHasSymmetricKey(testFlag bool) bool {
	return testFlag
}

func IfClientRequiredCert() bool {
	return true
}

func ClientInitTlsConfig() {
	config := &TlsConfig{}
	config.isClient = true
	//config.handshakeState =
}
