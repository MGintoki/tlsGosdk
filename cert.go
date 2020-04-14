package gosdk

import "time"

type certLoader interface {
	GetCert() string
	GetCertChain() []string
}

type cert struct {
	cert      string
	certChain string
	state     string
	notBefore time.Time
	notAfter  time.Time
}

func verifyCert(cert *cert) (stateCode string) {

	return ""
}
