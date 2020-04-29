package gosdk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pretty66/gosdk/errno"
	"time"
)

//func SendHandshake(handshake *Handshake) (out *Handshake, err error) {
//	client := http.Client{}
//	url := GetHSRequestRoute()
//	hsByte, err := json.Marshal(handshake)
//	if err != nil {
//		return out, err
//	}
//
//	request, err := http.NewRequest("POST", url, bytes.NewReader(hsByte))
//	if handshake.ActionCode == CLIENT_HELLO_CODE {
//		request.Method = "OPTION"
//	}
//	request.Header.Set("Content-Type", "application/json")
//	if err != nil {
//		return out, err
//	}
//	response, err := client.Do(request)
//	if err != nil {
//		return out, err
//	}
//	defer response.Body.Close()
//	err = json.NewDecoder(response.Body).Decode(&out)
//	return out, err
//
//}

type ClientInitState struct {
}

func (c *ClientInitState) currentState() int {
	return CLIENT_INIT_STATE
}

func (c *ClientInitState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case CLIENT_HELLO_CODE:
		clientHello := &ClientHello{
			IsClientEncryptRequired: tlsConfig.IsEncryptRequired,
			IsCertRequired:          tlsConfig.IsCertRequired,
			CipherSuites:            tlsConfig.CipherSuites,
		}
		clientHelloHandshake := &Handshake{
			Version:       "",
			HandshakeType: 0,
			ActionCode:    CLIENT_HELLO_CODE,
			SessionId:     tlsConfig.SessionId,
			SendTime:      time.Time{},
			ClientHello:   clientHello,
		}
		//fmt.Println("client hello handshake init ")
		//out, err = tlsConfig.SendHandshake(clientHelloHandshake)
		//fmt.Println("client hello sent")
		//if err != nil {
		//	return out, err
		//}
		//tlsConfig.HandshakeState = &ClientSentClientHelloState{}
		//tlsConfig.HandshakeMsgs[CLIENT_HELLO_CODE] = *clientHelloHandshake
		//return out, err
		return clientHelloHandshake, err

	default:
		return out, err

	}
	return
}

type ClientSentClientHelloState struct {
}

func (c *ClientSentClientHelloState) currentState() int {
	return CLIENT_SENT_CLIENT_HELLO_STATE
}

func (c *ClientSentClientHelloState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch handshake.ActionCode {
	case SERVER_HELLO_CODE:

	}
	return
}

type ClientReceivedServerHelloState struct {
}

func (c *ClientReceivedServerHelloState) currentState() int {
	return CLIENT_RECEIVED_SERVER_HELLO_STATE
}

func (c *ClientReceivedServerHelloState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case SERVER_HELLO_CODE:
		tlsConfig.CipherSuite = handshake.ServerHello.CipherSuite
		flag, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.VerifyCert(handshake.ServerHello.Cert, handshake.ServerHello.CertVerifyChain, handshake.ServerHello.PublicKey)
		if err != nil {

		}
		if !flag {
			return out, errno.CERT_VERIFY_ERROR
		}
		//如果客户端不能直接获取服务端的证书和公钥，使用server hello 里的证书以及公钥
		if tlsConfig.IsCertRequired {
			tlsConfig.Cert = handshake.ServerHello.Cert
			tlsConfig.CertChain = handshake.ServerHello.CertVerifyChain
			tlsConfig.PublicKey = handshake.ServerHello.PublicKey
		}
		tlsConfig.SessionId = handshake.SessionId
		//将来会有从本地获取部署指定路径的证书以及公钥
		symmetricKey := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.CreateSymmetricKey(tlsConfig.Randoms)
		tlsConfig.SymmetricKey = symmetricKey
		//使用公钥加密通信密钥
		symmetricKeyByte, err := json.Marshal(tlsConfig.SymmetricKey)
		////if err != nil {
		////	return out, errno.JSON_ERROR.Add("SymmetricKey Marshal error")
		////}
		encryptedSymmetricKey, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.AsymmetricKeyEncrypt(symmetricKeyByte, tlsConfig.PublicKey)
		if err != nil {
			return out, errno.ASYMMETRIC_ENCRYPT_ERROR.Add(err.Error())
		}
		//生成handshake
		clientKeyExchange := ClientKeyExchange{
			//SymmetricKey: encryptedSymmetricKey,
			SymmetricKey: encryptedSymmetricKey,
			MAC:          "",
		}
		clientKeyExchangeHandshake := &Handshake{
			Version:           "",
			HandshakeType:     0,
			ActionCode:        CLIENT_KEY_EXCHANGE_CODE,
			SessionId:         tlsConfig.SessionId,
			SendTime:          time.Time{},
			ClientKeyExchange: &clientKeyExchange,
		}
		tlsConfig.HandshakeMsgs[SERVER_HELLO_CODE] = *handshake
		tlsConfig.HandshakeMsgs[CLIENT_KEY_EXCHANGE_CODE] = *clientKeyExchangeHandshake
		//生成MAC摘要，填入clientKeyExchange中
		MAC, err := CreateNegotiateMAC(tlsConfig)
		MACEncrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyEncrypt(MAC, tlsConfig.SymmetricKey)
		if err != nil {
			return out, errno.CREATE_MAC_ERROR.Add("Client Create MAC Error")
		}
		MACEncryptedToStr := base64.StdEncoding.EncodeToString(MACEncrypted)
		clientKeyExchangeHandshake.ClientKeyExchange.MAC = MACEncryptedToStr
		fmt.Println("generate client key exchange")
		//out, err := tlsConfig.SendHandshake(clientKeyExchangeHandshake)
		//fmt.Println("sent client key exchange")
		//tlsConfig.HandshakeState = &ClientSentKeyExchangeState{}
		//if err != nil {
		//	return out, err
		//}
		//fmt.Println("received server Finished")
		//tlsConfig.HandshakeState = &ClientReceivedServerFinishedState{}
		//return out, err
		return clientKeyExchangeHandshake, err
	}
	return
}

type ClientSentKeyExchangeState struct {
}

func (c *ClientSentKeyExchangeState) currentState() int {
	return CLIENT_SENT_KEY_EXCHANGE_STATE
}

func (c *ClientSentKeyExchangeState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	return nil, nil
}

type ClientReceivedServerFinishedState struct {
}

func (c *ClientReceivedServerFinishedState) currentState() int {
	return CLIENT_RECEIVED_SERVER_FINISHED_STATE
}

func (c *ClientReceivedServerFinishedState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case SERVER_FINISHED_CODE:
		tlsConfig.HandshakeState = &ClientEncryptedConnectionState{}
	}
	return
}

type ClientNoEncryptConnectionState struct {
}

func (c *ClientNoEncryptConnectionState) currentState() int {
	return CLIENT_NO_ENCRYPT_CONNECTION_STATE
}

func (c *ClientNoEncryptConnectionState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	default:
		return
	}
}

type ClientEncryptedConnectionState struct {
}

func (c *ClientEncryptedConnectionState) currentState() int {
	return CLIENT_ENCRYPTED_CONNECTION_STATE
}

func (c *ClientEncryptedConnectionState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	switch actionCode {
	case SERVER_APP_DATA_CODE:
		//对appData的MAC进行一个验证
		data := handshake.AppData.Data
		dataByte, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return out, errno.BASE64_DECODE_ERROER.Add(err.Error())
		}
		dataDecrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(dataByte, tlsConfig.SymmetricKey)
		if err != nil {
			return out, errno.SYMMETRIC_KEY_DECRYPT_ERROR.Add(err.Error())
		}
		MACLocal := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.CreateMAC(dataDecrypted)
		MACReceivedByte, err := base64.StdEncoding.DecodeString(handshake.AppData.MAC)
		if err != nil {
			return nil, errno.BASE64_DECODE_ERROER.Add(err.Error())
		}
		MACReceived, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(MACReceivedByte, tlsConfig.SymmetricKey)
		if err != nil {
			return nil, errno.JSON_ERROR.Add(err.Error())
		}
		if string(MACLocal) != string(MACReceived) {
			return nil, errno.MAC_VERIFY_ERROR
		}

		return handshake, err
	}
	//case CLIENT_APP_DATA_CODE:
	//	out, err = tlsConfig.SendHandshake(handshake)
	//	if err != nil {
	//		return nil, errno.HANDSHAKE_ERROR.Add(err.Error())
	//	}
	//	if out.ActionCode == SERVER_APP_DATA_CODE {
	//		//对appData的MAC进行一个验证
	//		data := out.AppData.Data
	//		dataByte, err := base64.StdEncoding.DecodeString(data)
	//		if err != nil {
	//			return out, errno.BASE64_DECODE_ERROER.Add(err.Error())
	//		}
	//		dataDecrypted, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(dataByte, tlsConfig.SymmetricKey)
	//		if err != nil {
	//			return out, errno.SYMMETRIC_KEY_DECRYPT_ERROR.Add(err.Error())
	//		}
	//		MACLocal := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.CreateMAC(dataDecrypted)
	//		MACReceivedByte, err := base64.StdEncoding.DecodeString(out.AppData.MAC)
	//		if err != nil {
	//			return nil, errno.BASE64_DECODE_ERROER.Add(err.Error())
	//		}
	//		MACReceived, err := NewCipherSuiteModel(tlsConfig.CipherSuite).CipherSuiteInterface.SymmetricKeyDecrypt(MACReceivedByte, tlsConfig.SymmetricKey)
	//		if err != nil {
	//			return nil, errno.JSON_ERROR.Add(err.Error())
	//		}
	//		if string(MACLocal) != string(MACReceived) {
	//			return nil, errno.MAC_VERIFY_ERROR
	//		}
	//
	//	} else {
	//		return nil, errno.HANDSHAKE_ERROR.Add("Danger Connection")
	//	}
	//	return out, err
	//}
	//case CLIENT_CLOSE_NOTIFY_CODE:
	//	clientCloseNotify := &ClientCloseNotify{}
	//	handshake := &Handshake{
	//		Version:           "",
	//		HandshakeType:     0,
	//		ActionCode:        CLIENT_CLOSE_NOTIFY_CODE,
	//		SessionId:         handshake.SessionId,
	//		SendTime:          time.Time{},
	//		ClientCloseNotify: clientCloseNotify,
	//	}
	//	tlsConfig.HandshakeState = &ClientClosedState{}
	//	fmt.Println("Client State -> Client Closed")
	//	err = SaveTLSConfigToTlsConfigMap(CLIENT_TLS_CONFIG_FILE_PATH, *tlsConfig)
	//	if err != nil {
	//		return nil, err
	//	}
	//	fmt.Println("Save TlsConfig To Config Map")
	//	out, err = tlsConfig.SendHandshake(handshake)
	//	fmt.Println("Send Client Close Notify")
	//	return

	return
}

type ClientClosedState struct {
}

func (c *ClientClosedState) currentState() int {
	return CLIENT_CLOSED_STATE
}

func (c *ClientClosedState) handleAction(tlsConfig *TlsConfig, handshake *Handshake, actionCode int) (out *Handshake, err error) {
	return nil, nil
}
