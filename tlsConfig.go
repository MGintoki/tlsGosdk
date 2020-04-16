package gosdk

import (
	"time"
)

type TlsConfig struct {
	sessionId      string
	isClient       bool
	handshakeState StateMachineInterface
	isCertRequired bool
	serverName     string
	state          int
	cipherSuites   []int
	cipherSuite    int
	time           time.Duration
	timeout        time.Duration
	randoms        []string
	keypair        keypair
	symmetricKey   SymmetricKey
	cert           string
	certChain      []string
	handshakeMsgs  map[int]Handshake
	logs           []string
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
