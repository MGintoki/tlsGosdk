package gosdk

import "time"

type CertLoader interface {
	GetCert() string
	GetCertChain() []string
}

type Cert struct {
	cert      string
	certChain string
	state     string
	notBefore time.Time
	notAfter  time.Time
}

func verifyCert(cert *Cert) (stateCode string) {

	return ""
}
