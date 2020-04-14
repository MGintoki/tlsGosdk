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
func GetSessionInfo(sessionId, filepath string) *tlsConfig {
	return nil
}
