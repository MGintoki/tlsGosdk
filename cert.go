package gosdk

type CertLoader interface {
	GetCert(cipherSuite int) string
	GetCertChain(cipherSuite int) []string
}

func VerifyCert(cert []byte, certChain [][]byte, publicKey []byte) bool {

	return true
}
