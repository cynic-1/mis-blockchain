package Node

import (
	"MIS-BC/common"
	"MIS-BC/security/code"
	"encoding/json"
	"minlib/component"
	"minlib/logicface"
	"minlib/minsecurity"
	"minlib/minsecurity/crypto/cert"
	"minlib/packet"
)

type CertRequest struct {
	Identityidentifier string
}

type CertRespond struct {
	Code int
	Cert string
}

// HandleMIRMessage
// @Title    		handle
// @Description   	处理网络连接函数
// @Param			lf *logicface.LogicFace 接收到的网络连接
func (node *Node) HandleMIRMessage(lf *logicface.LogicFace) {
	for {
		interest, err := lf.ReceiveInterest(-1)
		if err != nil {
			common.Logger.Error(err)
			return
		}

		go node.CertRequestProcess(lf, interest)
	}
}

func (node *Node) CertRequestProcess(lf *logicface.LogicFace, interest *packet.Interest) {
	var certresponse CertRespond
	respondpacket := packet.Data{}
	respondpacket.SetName(interest.GetName())
	respondpacket.SetTTL(10)

	verifyerr := node.network.Keychain.VerifyInterest(interest)
	if verifyerr != nil {
		certresponse.Code = code.UNARTHORIZED
		certresponse.Cert = ""
		common.Logger.Error("verifyerr：", verifyerr)
	} else {
		payloadbytes := interest.GetValue()
		//respondpacket := packet.Data{}
		//respondpacket.SetName(interest.GetName())
		//respondpacket.SetTtl(10)

		var certrequest CertRequest
		err := json.Unmarshal(payloadbytes, &certrequest)
		if err != nil {
			common.Logger.Error(err)
		}
		common.Logger.Info("解析出MIR的证书请求为：", certrequest)
		if certrequest.Identityidentifier == "" {
			common.Logger.Error("identityidentifier required")
			certresponse.Code = code.BAD_REQUEST
			certresponse.Cert = ""
			cb, err := json.Marshal(certresponse)
			if err != nil {
				common.Logger.Error(err)
			}
			respondpacket.SetValue(cb)
			respondpacket.SetNoCache(true)
		} else {
			if certrequest.Identityidentifier == "/root" {
				i := node.mongo.GetOneIdentityFromDatabase("identityidentifier", "root")
				respondpacket.SetFreshnessPeriod(3600 * 1000)
				certresponse.Code = code.SUCCESS
				Ca := cert.Certificate{}
				err := Ca.FromPem(i.Cert, []byte(i.Passwd), minsecurity.SM4ECB)
				if err != err {
					common.Logger.Error(err)
				}
				str, err := Ca.ToPem([]byte(""), minsecurity.SM4ECB)
				if err != nil {
					common.Logger.Error(err)
				}
				certresponse.Cert = str
			} else if node.mongo.HasIdentityData("identityidentifier", certrequest.Identityidentifier) {
				i := node.mongo.GetOneIdentityFromDatabase("identityidentifier", certrequest.Identityidentifier)
				if i.IsValid == code.INVALID || i.IsValid == code.WITHOUT_CERT || i.IsValid == code.PENDING_REVIEW {
					certresponse.Code = code.BAD_REQUEST
					certresponse.Cert = ""
					respondpacket.SetNoCache(true)
				} else if i.IsValid == code.VALID {
					respondpacket.SetFreshnessPeriod(3600 * 1000)
					certresponse.Code = code.SUCCESS
					Ca := cert.Certificate{}
					err := Ca.FromPem(i.Cert, []byte(i.Passwd), minsecurity.SM4ECB)
					if err != err {
						common.Logger.Error(err)
					}
					str, err := Ca.ToPem([]byte(""), minsecurity.SM4ECB)
					if err != nil {
						common.Logger.Error(err)
					}
					certresponse.Cert = str
				}
			} else {
				respondpacket.SetNoCache(true)
				certresponse.Code = code.NOT_FOUND
				certresponse.Cert = ""
			}
			// id := i.ParseBCIdentityToCommon()
			common.Logger.Info("证书查询结果为：", certresponse)

		}

	}
	cb, err := json.Marshal(certresponse)
	if err != nil {
		common.Logger.Error(err)
	}
	respondpacket.SetValue(cb)

	if err := node.network.Keychain.SignData(&respondpacket); err != nil {
		common.Logger.Error(err)
	}

	if err := lf.SendData(&respondpacket); err != nil {
		common.Logger.Error(err)
	}

}

type CertRevocation struct {
	Identityidentifier string
}

// SendCertRevocationMessageToMIR
// @Title
// @Description
// @Param
func (node *Node) SendCertRevocationMessageToMIR(identityidentifier string) {
	lf := logicface.LogicFace{}
	if err := lf.InitWithUnixSocket("/tmp/mir.sock"); err != nil {
		common.Logger.Error(err)
		return
	}

	var cv CertRevocation
	cv.Identityidentifier = identityidentifier
	data, err := json.Marshal(cv)
	if err != nil {
		common.Logger.Error(err)
		return
	}

	name, err := component.CreateIdentifierByString(node.config.CertRespondforMIR) // /mir/cert
	if err != nil {
		common.Logger.Error("创建Identifier失败:", err)
		return
	}
	var interest packet.Interest
	interest.SetName(name)
	interest.SetCanBePrefix(true)
	interest.SetMustBeRefresh(true)
	interest.SetNonce(1234)
	interest.SetHopLimit(1234)
	interest.SetCongestionLevel(1234)
	interest.SetTTL(1234)
	interest.Payload.SetValue(data)

	err = node.network.Keychain.SignInterest(&interest)
	if err != nil {
		common.Logger.Error("兴趣包签名错误:", err)
		return
	}

	lf.SendInterest(&interest)
}
