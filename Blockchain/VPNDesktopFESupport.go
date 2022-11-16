package Node

import (
	"MIS-BC/MetaData"
	"MIS-BC/Network/network"
	"MIS-BC/common"
	"MIS-BC/security/code"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"minlib/minsecurity"
	"minlib/minsecurity/crypto/cert"
	"minlib/minsecurity/crypto/sm2"
	"runtime/debug"
	"time"
)

// HandleVPNPCFEMessage
// @Title    		handle
// @Description   	处理网络连接函数
// @Param			conn network.Connect 接收到的网络连接
func (node *Node) HandleVPNPCFEMessage(conn network.Connect) {
	// 随机生成一个10位的数字 作为连接ID 生成context字节点 并存储数值key:value
	connID := fmt.Sprintf("%09v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(1e10))
	ctx := context.WithValue(context.Background(), "conn_id", connID)
	// 存入连接池 锁住 防止高并发
	//network.DefaultConnPool.Mu.Lock()
	//network.DefaultConnPool.ConnMap[connID] = conn
	//network.DefaultConnPool.Mu.Unlock()
	//conn.GetConn().SetKeepAlivePeriod(10 * time.Second)
	//conn.GetConn().SetKeepAlive(true)
	err := conn.GetConn().SetReadDeadline(time.Now().Add(6 * time.Second))
	if err != nil {
		common.Logger.Warn("set readdeadline fail,err:", err)
		return
	}

	defer func() {
		if err := conn.Close(); err != nil {
			common.Logger.Error("handle conn fail,err:", err)
		}

		common.Logger.Debug("----------close the conn----------", connID, " from ", conn.GetRemote())

		if err := recover(); err != nil {
			common.Logger.Error("panic when program execute,err:", err)
			debug.PrintStack()
		}
	}()

	for {
		// 读取buf数据
		buf, err := conn.Read()
		if err != nil {
			common.Logger.Warn("read msg fail,err:", err)
			return
		}
		var resp = network.NewNetResponse()
		resp.SetConnect(conn)
		common.Logger.DebugfWithIdAndConn(ctx.Value("conn_id").(string), conn.GetRemote(), "The Server Received data: %v", string(buf))
		var req = network.NewNetRequest()
		// 读取buf解析成结构体 赋值给req
		err = req.SetJsonInfo(buf)
		if err != nil {
			common.Logger.ErrorfWithIdAndConn(ctx.Value("conn_id").(string), conn.GetRemote(), "Error Unmarshal Json Message, "+string(buf))
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "Error Unmarshal Json Message"
			goto LABLE
		}
		// 设置连接
		req.SetConnection(conn)

		if req.Type == "" || req.Command == "" || req.Parameters == nil {
			common.Logger.ErrorfWithIdAndConn(ctx.Value("conn_id").(string), conn.GetRemote(), "Error the Request Type is Null, "+string(buf))
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "Error the Request Type is Null"
		} else if req.Type == "identity-act" {
			switch req.Command {
			case "Registry":
				resp = node.IdentityRegistryforVPNFE(req, resp)
			case "RevokeRegistry":
				resp = node.IdentityRevokeRegistryForVPNFE(req, resp)
			case "Authentication":
				resp = node.IdentityAuthentication(req, resp)
			case "IsValidIdentity":
				resp = node.IsValidIdentity(req, resp)
			case "GetValidIdentity":
				resp = node.GetValidIdentity(req, resp)
			case "ResetPassword":
				resp = node.ResetPassword(req, resp)
			case "UploadEncryptedPrikey":
				resp = node.UploadEncryptedPrikey(req, resp)
			case "BindWeChat":
				resp = node.BindWeChatforVPNFE(req, resp)
			case "UnBindWeChat":
				resp = node.UnBindWeChatforVPNFE(req, resp)
			}
		}
	LABLE:
		// 从response中取出回复json
		respData := resp.GetJsonInfo()
		// 写入 发送给客户端
		err = conn.Write(respData)
		if err != nil {
			common.Logger.ErrorfWithIdAndConn(ctx.Value("conn_id").(string), conn.GetRemote(), "Error Send Json Message, "+string(respData))
		}
		common.Logger.DebugfWithIdAndConn(ctx.Value("conn_id").(string), conn.GetRemote(), "Finish the connection...")
		// 如果模式是短连接 直接return断开
		switch req.Header["Mode"] {
		case network.ShortConn:
			return
		case network.LongConn:
			continue
		default:
			return
		}
		//else {
		//	// TODO 如果header中没有sessionID的话 报错 没有授权
		//	if _, ok := req.Header["SessionId"]; ok == false {
		//		resp.Code = code.UNAUTHORIZED
		//		common.Logger.Error("not have sessionId")
		//		resp.ErrorMsg = "not have sessionId"
		//	}
		//	// TODO 如果存入的不是字符串 或者没有数据的话 报错 禁止
		//	sessionId, ok := req.Header["SessionId"].(string)
		//	if !ok {
		//		common.Logger.Error("sessionId is not string")
		//		resp.Code = code.FORBIDDEN
		//		resp.ErrorMsg = "sessionId is not string"
		//	}
		//	if object, ok := node.SessionCache.Get(sessionId); !ok {
		//		common.Logger.Error("the sessionId of cache is not existed or expired")
		//		resp.Code = code.FORBIDDEN
		//		resp.ErrorMsg = "the sessionId of cache is not existed or expired"
		//	} else {
		//		req.SetAttribute("admin", object)
		//	}
		//}

	}
}

//type AuthRequest struct {
//	IdentityIdentifier	string
//	Phone				string
//}

type VPNFERequest struct {
	IdentityIdentifier string
	Phone              string
	Pubkey             string
	PrikeyEncrypted    string
	PrePasswd          string
	Passwd             string
	VerificationCode   string
	IPIdentifier       string
	Code               string
}

// IdentityAuthentication TODO 定义一个专门解析前端请求的结构体
func (node *Node) IdentityAuthentication(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var r VPNFERequest
	err := json.Unmarshal(res.Parameters, &r)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "解析失败"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if r.IdentityIdentifier == "" || r.Phone == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.LESS_PARAMETER
		resp.ErrorMsg = "less parameter"
		return resp
	} else {
		vc := node.sms.GenerateVerificationCode()
		node.sms.VerificationCode.Set(r.Phone, &vc, 10*time.Minute)
		e := node.sms.Sendmessage(r.Phone)
		if e != nil {
			common.Logger.Error("send vc err: ", e.Error())
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = e.Error()
			return resp
		}
		resp.Code = code.SUCCESS
		resp.Data = nil

	}

	return resp
	// var response CommonResponse
	// 验证不更新修改记录
	// node.mongo.UpdateIdentityModifyRecordsforAuthentication(id)

	// 查询是否存在
	//if node.mongo.HasIdentityData("identityidentifier", r.IdentityIdentifier) {
	//	common.Logger.Error("数据库存在该身份标识，注册失败", r.IdentityIdentifier)
	//	resp.Code = code.BAD_REQUEST
	//	resp.ErrorMsg = "数据库存在该身份标识"
	//	return resp
	//}else if node.mongo.HasIdentityData("phone", r.Phone) {
	//	common.Logger.Error("数据库存在该手机号，注册失败", r.Phone)
	//	resp.Code = code.BAD_REQUEST
	//	resp.ErrorMsg = "数据库存在该手机号"
	//	return resp
	//}
	//// 如果存在的话 取出对应身份 和 root身份
	//identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
	//root := node.mongo.GetOneIdentityFromDatabase("identityidentifier", "root")
	//// 从root身份中取出证书
	//Ca := cert.Certificate{}
	//_ = Ca.FromPem(root.Cert, []byte(root.Passwd), minsecurity.SM4ECB)
	//// 对比两者身份是否一致
	//if id.Passwd != identity.Passwd {
	//	common.Logger.Error("身份注册信息不匹配")
	//	resp.Code = code.BAD_REQUEST
	//	resp.ErrorMsg = "身份信息不匹配，认证失败"
	//	return resp
	//}
	//if identity.IsValid == code.INVALID {
	//	common.Logger.Error("该身份不可用")
	//	resp.Code = code.BAD_REQUEST
	//	resp.ErrorMsg = "该身份不可用"
	//	return resp
	//}
	//if id.KeyParam.SignatureAlgorithm == MetaData.SM2WithSM3 {
	//	Cert := cert.Certificate{}
	//	err := Cert.FromPem(id.Cert, []byte(identity.Passwd), minsecurity.SM4ECB)
	//	if err != nil {
	//		resp.Code = code.BAD_REQUEST
	//		resp.ErrorMsg = "证书解析失败"
	//		return resp
	//	}
	//	flag, err := cert.Verify(Cert, Ca)
	//	if !flag || err != nil {
	//		resp.Code = code.BAD_REQUEST
	//		resp.ErrorMsg = "证书认证失败"
	//		return resp
	//	}
	//	resp.Code = code.SUCCESS

	//	resp.Data = nil
	//	return resp
	//} else {
	//	resp.Code = code.BAD_REQUEST
	//	resp.ErrorMsg = "未知的签名算法"
	//	common.Logger.Error("unknown signature algorithm")
	//	return resp
	//}
}

// IdentityRegistryforVPNFE 身份注册
//
// @Description: 提供给VPN前端的身份注册接口，该方法注册的身份无需管理员审核，直接生效
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) IdentityRegistryforVPNFE(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if id.Code == "" || id.IdentityIdentifier == "" || id.Pubkey == "" || id.Passwd == "" || id.PrikeyEncrypted == "" || id.Phone == "" || id.VerificationCode == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.LESS_PARAMETER
		resp.ErrorMsg = "less parameter"
		return resp
	}

	_, ok := node.RegistryCache.Get(id.IdentityIdentifier)
	if ok {
		common.Logger.Error(id.IdentityIdentifier, "已存在注册申请")
		resp.Code = code.NOT_ACCEPTABLE
		resp.ErrorMsg = "apply already exists, registration failed"
		return resp
	} else {
		node.RegistryCache.Set(id.IdentityIdentifier, nil, 10*time.Second)
	}

	vc, ok := node.sms.VerificationCode.Get(id.Phone)
	if !ok {
		common.Logger.Error(id.Phone, "Verification code expired or does not exist, please resend")
		resp.Code = code.UNARTHORIZED
		resp.ErrorMsg = "Verification code expired or does not exist, please resend"
		return resp
	}
	vcs := vc.(*string)
	if id.VerificationCode != *vcs {
		common.Logger.Error(id.Phone, "Verification code error")
		resp.Code = code.UNARTHORIZED
		resp.ErrorMsg = "Verification code error"
		return resp
	}
	if id.Code != "null" {
		//wxinfo, err := node.wechat.GetWxOpenIdFromOauth2(id.Code)
		//if err != nil {
		//	resp.Code = code.BAD_REQUEST
		//	resp.ErrorMsg = err.Error()
		//	common.Logger.Error("get wxinfo fail")
		//	return resp
		//}
		if node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
			common.Logger.Error("The identity already exists, registration failed", id.IdentityIdentifier)
			resp.Code = code.NOT_ACCEPTABLE
			resp.ErrorMsg = "The identity already exists, registration failed"
			node.RegistryCache.Delete(id.IdentityIdentifier)
			return resp
		} else if node.mongo.HasIdentityData("wxunionid", id.Code) {
			common.Logger.Error("Duplicate user wxunionid, registration failed")
			resp.Code = code.NOT_ACCEPTABLE
			resp.ErrorMsg = "Duplicate user wxunionid, registration failed"
			node.RegistryCache.Delete(id.IdentityIdentifier)
			return resp
		} else if node.mongo.HasIdentityData("pubkey", id.Pubkey) {
			common.Logger.Error("Duplicate user public key, registration failed")
			resp.Code = code.NOT_ACCEPTABLE
			resp.ErrorMsg = "Duplicate user public key, registration failed"
			node.RegistryCache.Delete(id.IdentityIdentifier)
			return resp
		} else {
			var transaction MetaData.Identity
			transaction.Type = "identity-act"
			transaction.Command = "Registry"
			transaction.IdentityIdentifier = id.IdentityIdentifier
			transaction.WXUnionID = id.Code
			transaction.KeyParam = MetaData.KeyParam{0, 0}
			transaction.Pubkey = id.Pubkey
			transaction.Passwd = id.Passwd
			transaction.Timestamp = time.Now().Format("2006-01-02 15:04:05")
			transaction.IsValid = code.VALID
			transaction.IPIdentifier = id.IPIdentifier
			transaction.ModifyRecords = append(transaction.ModifyRecords, MetaData.ModifyRecord{Type: "identity-act",
				Command: "Registry", Timestamp: time.Now().Format("2006-01-02 15:04:05")})
			transaction.Phone = id.Phone
			transaction.PrikeyEncrypted = id.PrikeyEncrypted

			// 填充证书内容
			pub := sm2.Sm2PublicKey{}
			pub.SetBytes([]byte(transaction.Pubkey))
			var pubkey minsecurity.PublicKey = &pub
			cert := cert.Certificate{}
			cert.Version = 0
			cert.SerialNumber = 1
			cert.PublicKey = pubkey
			cert.SignatureAlgorithm = 0
			cert.PublicKeyAlgorithm = 0
			cert.IssueTo = transaction.IdentityIdentifier
			cert.Issuer = "/root"
			cert.NotBefore = time.Now().Unix()
			cert.NotAfter = time.Now().AddDate(1, 0, 0).Unix()
			cert.KeyUsage = minsecurity.CertSign
			cert.IsCA = false
			cert.Timestamp = time.Now().Unix()

			pri := sm2.Sm2PrivateKey{}
			pri.SetBytes([]byte(node.keyManager.GetPriKey()))
			var prikey minsecurity.PrivateKey = &pri
			err := cert.SignCert(prikey)
			if err != nil {
				common.Logger.Error(err)
			}

			c, err := cert.ToPem([]byte(transaction.Passwd), 0)
			if err != nil {
				common.Logger.Error("Certificate issuance failed：", err)
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "Certificate issuance failed"
				node.RegistryCache.Delete(id.IdentityIdentifier)
			} else {
				var transactionHeader MetaData.TransactionHeader
				transactionHeader.TXType = MetaData.IdentityAction
				transaction.Cert = c
				resp.Code = code.SUCCESS
				//data, err := json.Marshal(transaction)
				//if err != nil {
				//	common.Logger.Error("身份解析失败：", err)
				//	resp.Code = code.BAD_REQUEST
				//	resp.ErrorMsg = "身份解析失败"
				//}
				resp.Data = []byte(id.Code)
				common.Logger.Info("身份申请注册中")
				node.txPool.PushbackTransaction(transactionHeader, &transaction)
				node.registryList[transaction.Pubkey] = node.mongo.Height
				node.RegistryCache.Set(id.IdentityIdentifier, &transaction, 3600*time.Second)

				i := transaction.ParseBCIdentityToCommon()
				err = node.network.Keychain.SaveIdentity(&i, true)
				if err != nil {
					common.Logger.Error(err)
				}
				// common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())
			}
		}
	} else if id.Code == "null" {
		if node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
			common.Logger.Error("The identity already exists, registration failed", id.IdentityIdentifier)
			resp.Code = code.NOT_ACCEPTABLE
			resp.ErrorMsg = "The identity already exists, registration failed"
			node.RegistryCache.Delete(id.IdentityIdentifier)
			return resp
		} else if node.mongo.HasIdentityData("pubkey", id.Pubkey) {
			common.Logger.Error("Duplicate user public key, registration failed")
			resp.Code = code.NOT_ACCEPTABLE
			resp.ErrorMsg = "Duplicate user public key, registration failed"
			node.RegistryCache.Delete(id.IdentityIdentifier)
			return resp
		} else {
			var transaction MetaData.Identity
			transaction.Type = "identity-act"
			transaction.Command = "Registry"
			transaction.IdentityIdentifier = id.IdentityIdentifier
			transaction.WXUnionID = ""
			transaction.KeyParam = MetaData.KeyParam{0, 0}
			transaction.Pubkey = id.Pubkey
			transaction.Passwd = id.Passwd
			transaction.Timestamp = time.Now().Format("2006-01-02 15:04:05")
			transaction.IsValid = code.VALID
			transaction.IPIdentifier = id.IPIdentifier
			transaction.ModifyRecords = append(transaction.ModifyRecords, MetaData.ModifyRecord{Type: "identity-act",
				Command: "Registry", Timestamp: time.Now().Format("2006-01-02 15:04:05")})
			transaction.Phone = id.Phone
			transaction.PrikeyEncrypted = id.PrikeyEncrypted

			// 填充证书内容
			pub := sm2.Sm2PublicKey{}
			pub.SetBytes([]byte(transaction.Pubkey))
			var pubkey minsecurity.PublicKey = &pub
			cert := cert.Certificate{}
			cert.Version = 0
			cert.SerialNumber = 1
			cert.PublicKey = pubkey
			cert.SignatureAlgorithm = 0
			cert.PublicKeyAlgorithm = 0
			cert.IssueTo = transaction.IdentityIdentifier
			cert.Issuer = "/root"
			cert.NotBefore = time.Now().Unix()
			cert.NotAfter = time.Now().AddDate(1, 0, 0).Unix()
			cert.KeyUsage = minsecurity.CertSign
			cert.IsCA = false
			cert.Timestamp = time.Now().Unix()

			pri := sm2.Sm2PrivateKey{}
			pri.SetBytes([]byte(node.keyManager.GetPriKey()))
			var prikey minsecurity.PrivateKey = &pri
			err := cert.SignCert(prikey)
			if err != nil {
				common.Logger.Error(err)
			}

			c, err := cert.ToPem([]byte(transaction.Passwd), 0)
			if err != nil {
				common.Logger.Error("Certificate issuance failed：", err)
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "Certificate issuance failed"
				node.RegistryCache.Delete(id.IdentityIdentifier)
			} else {
				var transactionHeader MetaData.TransactionHeader
				transactionHeader.TXType = MetaData.IdentityAction
				transaction.Cert = c
				resp.Code = code.SUCCESS
				//data, err := json.Marshal(transaction)
				//if err != nil {
				//	common.Logger.Error("身份解析失败：", err)
				//	resp.Code = code.BAD_REQUEST
				//	resp.ErrorMsg = "身份解析失败"
				//}
				resp.Data = []byte("")
				common.Logger.Info("身份申请注册中")
				go node.txPool.PushbackTransaction(transactionHeader, &transaction)
				node.registryList[transaction.Pubkey] = node.mongo.Height
				node.RegistryCache.Set(id.IdentityIdentifier, &transaction, 3600*time.Second)

				i := transaction.ParseBCIdentityToCommon()
				err = node.network.Keychain.SaveIdentity(&i, true)
				if err != nil {
					common.Logger.Error(err)
				}
				// common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())
			}
		}
	}
	return resp
}

// IdentityRevokeRegistryForVPNFE 身份注册
//
// @Description: 提供给VPN前端的撤销身份注册接口
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) IdentityRevokeRegistryForVPNFE(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if id.IdentityIdentifier == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.LESS_PARAMETER
		resp.ErrorMsg = "less parameter"
		return resp
	}
	v, ok := node.RegistryCache.Get(id.IdentityIdentifier)
	if ok && v != nil {
		if node.config.MyAddress.Port == 5010 {
			err = node.SendRemoveUserToVMS(id.IdentityIdentifier)
			if err != nil && err.Error() != "user not exist" {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = err.Error()
				return resp
			}
		}

		var transaction MetaData.Identity
		transaction.Type = "identity-act"
		transaction.Command = "DestroyByIdentityIdentifier"
		transaction.IdentityIdentifier = id.IdentityIdentifier

		var transactionHeader MetaData.TransactionHeader
		transactionHeader.TXType = MetaData.IdentityAction
		node.txPool.PushbackTransaction(transactionHeader, &transaction)

		resp.Code = code.SUCCESS
		resp.Data = nil

		if node.config.IsMINConn {
			node.SendCertRevocationMessageToMIR(id.IdentityIdentifier)
		}
	} else {
		if node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
			// identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
			var transaction MetaData.Identity
			transaction.Type = "identity-act"
			transaction.Command = "DestroyByIdentityIdentifier"
			transaction.IdentityIdentifier = id.IdentityIdentifier

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			//i := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
			//flag, err := node.network.Keychain.DeleteIdentityByName(transaction.IdentityIdentifier, i.Passwd)
			//if err != nil {
			//	common.Logger.Error(err)
			//} else if flag == true {
			//	common.Logger.Info("sqlite删除身份成功")
			//} else {
			//	common.Logger.Info("sqlite删除身份失败")
			//}

			resp.Code = code.SUCCESS
			resp.Data = nil

			if node.config.IsMINConn {
				node.SendCertRevocationMessageToMIR(id.IdentityIdentifier)
			}
		} else {
			resp.Code = code.NOT_FOUND
			resp.ErrorMsg = "The user does not exist in the database, or the registration application has not been completed, please try again later"
		}
	}

	return resp
}

type GetIdentityRespond struct {
	IdentityIdentifier string `msg:"identityidentifier"` //身份标识
	Pubkey             string `msg:"pubkey"`             //公钥
	PrikeyEncrypted    string `msg:"prikeyencrypted"`    //加密后的私钥
	Cert               string `msg:"cert"`               //用户证书
	Phone              string `msg:"phone"`              //手机号码
	WXUnionID          string `msg:"wxunionid"`          //微信ID
}

// IsValidIdentity 新设备上判断是否是已注册的身份
//
// @Description: 提供给VPN前端的判断是否是已注册的身份的接口
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) IsValidIdentity(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if id.IdentityIdentifier == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.LESS_PARAMETER
		resp.ErrorMsg = "less parameter"
		return resp
	}

	rc, ok := node.RegistryCache.Get(id.IdentityIdentifier)
	if ok {
		identity := rc.(*MetaData.Identity)
		if identity.IsValid == code.INVALID {
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "The identity has been disabled and the acquisition failed"
			return resp
		} else if identity.IsValid == code.WITHOUT_CERT {
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "The identity certificate has been revoked and failed to obtain"
			return resp
		} else {
			resp.Code = code.SUCCESS
			resp.Data = nil
		}
	} else {
		if !node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
			common.Logger.Error("The identity does not exist, and the acquisition fails", id.IdentityIdentifier)
			resp.Code = code.NOT_FOUND
			resp.ErrorMsg = "The identity does not exist, and the acquisition fails"
			return resp
		} else {
			Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
			if Identity.IsValid == code.INVALID {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "The identity has been disabled and the acquisition failed"
				return resp
			} else if Identity.IsValid == code.WITHOUT_CERT {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "The identity certificate has been revoked and failed to obtain"
				return resp
			} else {
				resp.Code = code.SUCCESS
				resp.Data = nil
			}
		}
	}
	return resp
}

// GetValidIdentity 新设备上获取已注册的身份信息
//
// @Description: 提供给VPN前端的身份获取接口
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) GetValidIdentity(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if id.Code == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.LESS_PARAMETER
		resp.ErrorMsg = "less parameter"
		return resp
	} else if id.Code == "null" {
		if id.IdentityIdentifier == "" || id.Passwd == "" || id.Phone == "" || id.VerificationCode == "" {
			common.Logger.Error("less parameter")
			resp.Code = code.LESS_PARAMETER
			resp.ErrorMsg = "less parameter"
			return resp
		}
		vc, ok := node.sms.VerificationCode.Get(id.Phone)
		if !ok {
			common.Logger.Error(id.Phone, "Verification code expired or does not exist, please resend")
			resp.Code = code.UNARTHORIZED
			resp.ErrorMsg = "Verification code expired or does not exist, please resend"
			return resp
		}
		vcs := vc.(*string)
		if id.VerificationCode != *vcs {
			common.Logger.Error(id.Phone, "Verification code error")
			resp.Code = code.UNARTHORIZED
			resp.ErrorMsg = "Verification code error"
			return resp
		}
		rc, ok := node.RegistryCache.Get(id.IdentityIdentifier)
		if ok {
			identity := rc.(*MetaData.Identity)
			if identity.IsValid == code.INVALID {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "The identity has been disabled and the acquisition failed"
				return resp
			} else if identity.IsValid == code.WITHOUT_CERT {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "The identity certificate has been revoked and failed to obtain"
				return resp
			} else if id.Passwd != identity.Passwd {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "Wrong password"
				return resp
			} else if identity.Phone != "" && id.Phone != identity.Phone {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "The identity and mobile phone number do not match, verification failed"
				return resp
			} else if identity.PrikeyEncrypted == "" {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "Please upload the private key information from the device with the private key"
				return resp
			} else {
				resp.Code = code.SUCCESS
				var gr GetIdentityRespond
				gr.IdentityIdentifier = identity.IdentityIdentifier
				gr.Phone = identity.Phone
				gr.PrikeyEncrypted = identity.PrikeyEncrypted
				gr.Pubkey = identity.Pubkey
				gr.Cert = identity.Cert
				gr.WXUnionID = identity.WXUnionID
				data, err := json.Marshal(gr)
				if err != nil {
					common.Logger.Error("Identity resolution failed: ", err)
					resp.Code = code.BAD_REQUEST
					resp.ErrorMsg = "Identity resolution failed"
				}
				resp.Data = data
			}
		} else {
			if !node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
				common.Logger.Error("The identity does not exist, and the acquisition fails", id.IdentityIdentifier)
				resp.Code = code.NOT_FOUND
				resp.ErrorMsg = "The identity does not exist, and the acquisition fails"
				return resp
			} else {
				Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
				if Identity.IsValid == code.INVALID {
					resp.Code = code.BAD_REQUEST
					resp.ErrorMsg = "The identity has been disabled and the acquisition failed"
					return resp
				} else if Identity.IsValid == code.WITHOUT_CERT {
					resp.Code = code.BAD_REQUEST
					resp.ErrorMsg = "The identity certificate has been revoked and failed to obtain"
					return resp
				} else if id.Passwd != Identity.Passwd {
					resp.Code = code.BAD_REQUEST
					resp.ErrorMsg = "Wrong password"
					return resp
				} else if Identity.Phone != "" && id.Phone != Identity.Phone {
					resp.Code = code.BAD_REQUEST
					resp.ErrorMsg = "The identity and mobile phone number do not match, verification failed"
					return resp
				} else if Identity.PrikeyEncrypted == "" {
					resp.Code = code.BAD_REQUEST
					resp.ErrorMsg = "Please upload the private key information from the device with the private key"
					return resp
				} else {
					resp.Code = code.SUCCESS
					var gr GetIdentityRespond
					gr.IdentityIdentifier = Identity.IdentityIdentifier
					gr.Phone = Identity.Phone
					gr.PrikeyEncrypted = Identity.PrikeyEncrypted
					gr.Pubkey = Identity.Pubkey
					gr.Cert = Identity.Cert
					gr.WXUnionID = Identity.WXUnionID
					data, err := json.Marshal(gr)
					if err != nil {
						common.Logger.Error("Identity resolution failed: ", err)
						resp.Code = code.BAD_REQUEST
						resp.ErrorMsg = "Identity resolution failed"
					}
					resp.Data = data
				}
			}
		}
	} else {
		wxinfo, err := node.wechat.GetWxOpenIdFromOauth2(id.Code)
		if err != nil {
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = err.Error()
			common.Logger.Error("get wxinfo fail")
			return resp
		}
		if node.mongo.HasIdentityData("wxunionid", wxinfo.Unionid) {
			Identity := node.mongo.GetOneIdentityFromDatabase("wxunionid", wxinfo.Unionid)
			if Identity.IsValid == code.INVALID {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "The identity has been disabled and the acquisition failed"
				return resp
			} else if Identity.IsValid == code.WITHOUT_CERT {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "The identity certificate has been revoked and failed to obtain"
				return resp
			} else if Identity.PrikeyEncrypted == "" {
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "Please upload the private key information from the device with the private key"
				return resp
			} else {
				resp.Code = code.SUCCESS
				var gr GetIdentityRespond
				gr.IdentityIdentifier = Identity.IdentityIdentifier
				gr.Phone = Identity.Phone
				gr.PrikeyEncrypted = Identity.PrikeyEncrypted
				gr.Pubkey = Identity.Pubkey
				gr.Cert = Identity.Cert
				gr.WXUnionID = Identity.WXUnionID
				data, err := json.Marshal(gr)
				if err != nil {
					common.Logger.Error("Identity resolution failed: ", err)
					resp.Code = code.BAD_REQUEST
					resp.ErrorMsg = "Identity resolution failed"
				}
				resp.Data = data
			}
		} else {
			common.Logger.Error("The identity does not exist, and the acquisition fails")
			resp.Code = code.NOT_FOUND
			resp.ErrorMsg = "The identity does not exist, and the acquisition fails"
			var gr GetIdentityRespond
			gr.IdentityIdentifier = ""
			gr.Phone = ""
			gr.PrikeyEncrypted = ""
			gr.Pubkey = ""
			gr.Cert = ""
			gr.WXUnionID = wxinfo.Unionid
			data, err := json.Marshal(gr)
			if err != nil {
				common.Logger.Error("Identity resolution failed: ", err)
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "Identity resolution failed"
			}
			resp.Data = data
			return resp
		}
	}

	return resp
}

// BindWeChatforVPNFE 微信绑定身份
//
// @Description: 微信绑定身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) BindWeChatforVPNFE(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if id.Code == "" || id.IdentityIdentifier == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.LESS_PARAMETER
		resp.ErrorMsg = "less parameter"
		return resp
	}

	//wxinfo, err := node.wechat.GetWxOpenIdFromOauth2(id.Code)
	//if err != nil {
	//	resp.Code = code.BAD_REQUEST
	//	resp.ErrorMsg = err.Error()
	//	common.Logger.Error("get wxinfo fail")
	//}

	if !node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
		common.Logger.Error("数据库不存在该身份标识，绑定失败", id.IdentityIdentifier)
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "数据库不存在该身份标识"
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
		if node.mongo.HasIdentityData("wxunionid", id.Code) || identity.WXUnionID != "" {
			common.Logger.Error("该微信已经绑定过身份，绑定失败")
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "该微信已经绑定过身份，绑定失败"
		} else {
			var transaction MetaData.Identity
			transaction = identity
			transaction.Type = "identity-act"
			transaction.Command = "UnboundWeChat"
			transaction.IdentityIdentifier = id.IdentityIdentifier
			transaction.WXUnionID = id.Code

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			resp.Code = code.SUCCESS
			resp.Data = nil
			node.mongo.UpdateIdentityModifyRecordsforVPN(transaction)

		}
	}
	return resp
}

// UnBindWeChatforVPNFE 身份解绑微信
//
// @Description: 身份解绑微信
// @receiver node
// @param res
// @param conn
//
func (node *Node) UnBindWeChatforVPNFE(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if id.IdentityIdentifier == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.LESS_PARAMETER
		resp.ErrorMsg = "less parameter"
		return resp
	}

	if !node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
		common.Logger.Error("数据库不存在该身份标识，解绑失败", id.IdentityIdentifier)
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "数据库不存在该身份标识"
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
		if identity.WXUnionID == "" {
			common.Logger.Error("该微信尚未绑定过身份，解绑失败")
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "该微信尚未绑定过身份，解绑失败"
		} else {
			var transaction MetaData.Identity
			transaction = identity
			transaction.Type = "identity-act"
			transaction.Command = "UnboundWeChat"
			transaction.IdentityIdentifier = id.IdentityIdentifier
			transaction.WXUnionID = ""

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			//i := transaction.ParseBCIdentityToCommon()
			//err := node.network.Keychain.SaveIdentity(&i, true)
			//if err != nil {
			//	common.Logger.Error(err)
			//}
			//common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

			resp.Code = code.SUCCESS
			resp.Data = nil
			node.mongo.UpdateIdentityModifyRecordsforVPN(transaction)
		}
	}
	return resp
}

func (node *Node) ResetPassword(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	if err != nil {
		common.Logger.Error("parse identity fail")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		return resp
	} else if id.IdentityIdentifier == "" || id.PrePasswd == "" || id.Passwd == "" || id.PrikeyEncrypted == "" || id.Phone == "" || id.VerificationCode == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "less parameter"
		return resp
	}
	vc, ok := node.sms.VerificationCode.Get(id.Phone)
	if !ok {
		common.Logger.Error(id.Phone, "Verification code expired or does not exist, please resend")
		resp.Code = code.UNARTHORIZED
		resp.ErrorMsg = "Verification code expired or does not exist, please resend"
		return resp
	}
	vcs := vc.(*string)
	if id.VerificationCode != *vcs {
		common.Logger.Error(id.Phone, "Verification code error")
		resp.Code = code.UNARTHORIZED
		resp.ErrorMsg = "Verification code error"
		return resp
	}

	if !node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
		common.Logger.Error("The identity does not exist, the modification failed", id.IdentityIdentifier)
		resp.Code = code.NOT_FOUND
		resp.ErrorMsg = "The identity does not exist, the modification failed"
		return resp
	} else {
		Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
		if id.PrePasswd != Identity.Passwd {
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "Wrong password"
			return resp
		} else if Identity.Phone != "" && id.Phone != Identity.Phone {
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "The identity and mobile phone number do not match, the modification failed"
			return resp
		} else {
			var transaction MetaData.Identity
			transaction = Identity
			transaction.Type = "identity-act"
			transaction.Command = "ResetPassword"
			transaction.IdentityIdentifier = id.IdentityIdentifier
			transaction.Passwd = id.Passwd
			transaction.PrikeyEncrypted = id.PrikeyEncrypted

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			go node.txPool.PushbackTransaction(transactionHeader, &transaction)

			i := transaction.ParseBCIdentityToCommon()
			err := node.network.Keychain.SaveIdentity(&i, true)
			if err != nil {
				common.Logger.Error(err)
			}
			node.mongo.UpdateIdentityModifyRecordsforVPN(transaction)

			// common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

			resp.Code = code.SUCCESS
			resp.Data = nil

		}
	}
	return resp
}

func (node *Node) UploadEncryptedPrikey(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id VPNFERequest
	err := json.Unmarshal(res.Parameters, &id)
	if err != nil {
		common.Logger.Error("parse identity fail")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		return resp
	} else if id.IdentityIdentifier == "" || id.Passwd == "" || id.PrikeyEncrypted == "" || id.Phone == "" || id.VerificationCode == "" {
		common.Logger.Error("less parameter")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "less parameter"
		return resp
	}
	vc, ok := node.sms.VerificationCode.Get(id.Phone)
	if !ok {
		common.Logger.Error(id.Phone, "Verification code expired or does not exist, please resend")
		resp.Code = code.UNARTHORIZED
		resp.ErrorMsg = "Verification code expired or does not exist, please resend"
		return resp
	}
	vcs := vc.(*string)
	if id.VerificationCode != *vcs {
		common.Logger.Error(id.Phone, "Verification code error")
		resp.Code = code.UNARTHORIZED
		resp.ErrorMsg = "Verification code error"
		return resp
	}

	if !node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
		common.Logger.Error("The identity does not exist, and the acquisition fails", id.IdentityIdentifier)
		resp.Code = code.NOT_FOUND
		resp.ErrorMsg = "The identity does not exist, and the acquisition fails"
		return resp
	} else {
		Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
		if id.Passwd != Identity.Passwd {
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "Wrong password"
			return resp
		} else if Identity.Phone != "" || Identity.PrikeyEncrypted != "" {
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "The identity has uploaded a private key"
			return resp
		} else {
			var transaction MetaData.Identity
			transaction = Identity
			transaction.Type = "identity-act"
			transaction.Command = "UploadEncryptedPrikey"
			transaction.IdentityIdentifier = id.IdentityIdentifier
			transaction.PrikeyEncrypted = id.PrikeyEncrypted
			transaction.Phone = id.Phone

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			go node.txPool.PushbackTransaction(transactionHeader, &transaction)

			i := transaction.ParseBCIdentityToCommon()
			err := node.network.Keychain.SaveIdentity(&i, true)
			if err != nil {
				common.Logger.Error(err)
			}
			// common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

			resp.Code = code.SUCCESS
			resp.Data = nil

		}
	}
	return resp
}
