package gosdk

type TlsServer struct {
	ServerInfo string     `json:"serverInfo"`
	ListenPath string     `json:"listenPath"`
	TlsConfig  *TlsConfig `json:"tlsConfig"`
}

//
//func initServerTlsConfig(reqUrl string, tmpIdn Idn) (out *TlsConfig, err error) {
//	tlsConfig := &TlsConfig{
//		SessionId:             "",
//		IsClient:              false,
//		CurrentInfo:           tmpIdn,
//		TargetInfo:            tmpIdn,
//		RequestUrl:            reqUrl,
//		HandshakeState:        nil,
//		IsEncryptRequired:     ifServerNeedTls(tmpIdn),
//		IsCertRequired:        isServerCertRequired(tmpIdn),
//		State:                 TLS_STATE_ACTIVING,
//		CipherSuites:          getServerCipherSuites(tmpIdn),
//		CipherSuite:           0,
//		Time:                  time.Time{},
//		Timeout:               0,
//		Randoms:               []string{},
//		PrivateKey:            nil,
//		PublicKey:             nil,
//		SymmetricKey:          nil,
//		SymmetricKeyCreatedAt: time.Time{},
//		SymmetricKeyExpiresAt: time.Time{},
//		Cert:                  nil,
//		CertChain:             nil,
//		CertLoader:            nil,
//		HandshakeMsgs:         map[int]Handshake{},
//		Logs:                  []string{},
//	}
//	timeOut, KeyTimeOut, isReuse, err := getServerInitInfo(tmpIdn)
//	if err != nil {
//		return nil, err
//	}
//	tlsConfig.Timeout = timeOut
//	tlsConfig.SymmetricKeyExpiresAt = tlsConfig.SymmetricKeyCreatedAt.Add(KeyTimeOut)
//	tlsConfig.IsReuse = isReuse
//	cert, certChain, publicKey, privateKey, err := getServerCert(tmpIdn)
//	if err != nil {
//		return nil, err
//	}
//	tlsConfig.Cert = cert
//	tlsConfig.CertChain = certChain
//	tlsConfig.PublicKey = publicKey
//	tlsConfig.PrivateKey = privateKey
//	tlsConfig.HandshakeState = &ServerInitState{}
//	return tlsConfig, err
//}
//
//func ifServerNeedTls(currentInfo Idn) bool {
//	//if currentInfo.AppKey != targetInfo.AppKey {
//	//	return true
//	//}
//	if currentInfo.AppKey != "123456" {
//		return true
//	}
//	return false
//}
//
//func isServerCertRequired(currentInfo Idn) bool {
//	//if currentInfo.AppKey != targetInfo.AppKey {
//	//	return true
//	//}
//	if currentInfo.AppKey == "123456" {
//		return true
//	}
//	return false
//}
//
//func getServerCipherSuites(currentInfo Idn) (out []int) {
//	out = append(out, cipherSuites.CIPHER_SUITE_MAP["ECDSA_AES256_CBC_SHA256"])
//	out = append(out, cipherSuites.CIPHER_SUITE_MAP["RSA_AES_CBC_SHA256"])
//	return
//}
//
//func getServerInitInfo(currentInfo Idn) (timeOut time.Duration, keyTimeOut time.Duration, isReuse bool, err error) {
//	return TIMEOUT * time.Second, KEY_TIME_OUT * time.Hour, true, nil
//}
//
//func getServerCert(currentInfo Idn) (outCert []byte, outCertChain []byte, outPublicKey []byte, outPrivateKey []byte, err error) {
//	return []byte(TestCert), []byte(TestChain), []byte(TestPublicKey), []byte(TestPrivateKey), nil
//}
