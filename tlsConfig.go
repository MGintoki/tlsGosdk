package gosdk

import (
	"time"
)

type tlsConfig struct {
	sessionId      string
	isClient       bool
	handshakeState string
	isCertRequired bool
	serverName     string
	state          string
	cipherSuites   cipherSuite
	cipherSuite    cipherSuite
	time           time.Time
	timeout        time.Time
	randoms        []string
	keypair        keypair
	symmetricKey   symmetricKey
	cert           string
	certChain      []string
	handshakeMsgs  []handshake
	logs           []string
}

//根据sessionId实例化一个tlsConfig
func ReuseSession(sessionId, filepath string) *tlsConfig {
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
	config := &tlsConfig{}
	config.isClient = true
	//config.handshakeState =
}
