package Node

import (
	"MIS-BC/MetaData"
	"MIS-BC/Network/network"
	"MIS-BC/common"
	"MIS-BC/security/code"
	"errors"
	"minlib/minsecurity"
	"minlib/minsecurity/crypto/cert"
	"minlib/minsecurity/crypto/sm2"
	"runtime/debug"
	"strings"
	"sync"

	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// HandleVPNMGMTMessage
// @Title    		handle
// @Description   	处理网络连接函数
// @Param			conn network.Connect 接收到的网络连接
func (node *Node) HandleVPNMGMTMessage(conn network.Connect) {
	// 随机生成一个10位的数字 作为连接ID 生成context字节点 并存储数值key:value
	connID := fmt.Sprintf("%09v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(1e10))
	ctx := context.WithValue(context.Background(), "conn_id", connID)
	// 存入连接池 锁住 防止高并发
	//network.DefaultConnPool.Mu.Lock()
	//network.DefaultConnPool.ConnMap[connID] = conn
	//network.DefaultConnPool.Mu.Unlock()
	err := conn.GetConn().SetReadDeadline(time.Now().Add(6 * time.Second))
	if err != nil {
		common.Logger.Warn("set readdeadline fail,err:", err)
		return
	}

	defer func() {
		if err := conn.Close(); err != nil {
			common.Logger.Error("handle conn fail,err:", err)
		}

		common.Logger.Debug("----------close the conn----------", connID)

		if err := recover(); err != nil {
			common.Logger.Error("panic when program execute,err:", err)
			debug.PrintStack()
		}
		//conn.Close()
		////network.DefaultConnPool.Mu.Lock()
		////delete(network.DefaultConnPool.ConnMap, connID)
		////network.DefaultConnPool.Mu.Unlock()
		//common.Logger.Debug("---------delete [%s] conn---------", connID)
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

		if req.Type == "" || req.Command == "" || req.Method == "" {
			common.Logger.ErrorfWithIdAndConn(ctx.Value("conn_id").(string), conn.GetRemote(), "Error the Request Type is Null, "+string(buf))
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "Error the Request Type is Null"
		} else if req.Type == "identity-act" {
			switch req.Command {
			case "Registry":
				resp = node.IdentityRegistryforVPN(req, resp)
			case "Authentication":
				resp = node.IdentityAuthentication(req, resp)
			case "RevokeRegistry":
				resp = node.IdentityRevokeRegistryForVMS(req, resp)
			case "GetAllIdentity":
				resp = node.GetAllIdentity(req, resp)
			case "UploadPhone":
				resp = node.UploadPhone(req, resp)

			}
		} else if req.Type == "userlog" {
			switch req.Command {
			case "UploadUserLog":
				resp = node.UploadUserLog(req, resp)
			case "GetPageNormalLogsByTimestamp":
				resp = node.GetPageNormalLogsByTimestamp(req, resp)
			case "GetPageWarningLogsByTimestamp":
				resp = node.GetPageWarningLogsByTimestamp(req, resp)
			case "GetPageNormalLogsByUserNameAndTimestamp":
				resp = node.GetPageNormalLogsByUserNameAndTimestamp(req, resp)
			case "GetPageWarningLogsByUserNameAndTimestamp":
				resp = node.GetPageWarningLogsByUserNameAndTimestamp(req, resp)
			case "GetAllNormalLogsByTimestamp":
				resp = node.GetAllNormalLogsByTimestamp(req, resp)
			case "GetAllWarningLogsByTimestamp":
				resp = node.GetAllWarningLogsByTimestamp(req, resp)
			case "GetAllNormalLogsByUGroupIDAndTimestamp":
				resp = node.GetAllNormalLogsByUGroupIDAndTimestamp(req, resp)
			case "GetPageNormalLogsByUGroupIDAndTimestamp":
				resp = node.GetPageNormalLogsByUGroupIDAndTimestamp(req, resp)
			case "GetAllWarningLogsByUGroupIDAndTimestamp":
				resp = node.GetAllWarningLogsByUGroupIDAndTimestamp(req, resp)
			case "GetPageWarningLogsByUGroupIDAndTimestamp":
				resp = node.GetPageWarningLogsByUGroupIDAndTimestamp(req, resp)
			case "GetNormalLogsAnalysis":
				resp = node.GetNormalLogsAnalysis(req, resp)
			case "GetWarningLogsAnalysis":
				resp = node.GetWarningLogsAnalysis(req, resp)
			case "GetNormalLogsAnalysisByUGroupID":
				resp = node.GetNormalLogsAnalysisByUGroupID(req, resp)
			case "GetWarningLogsAnalysisByUGroupID":
				resp = node.GetWarningLogsAnalysisByUGroupID(req, resp)
			case "getUGroupLogNumByUGroupID":
				resp = node.getUGroupLogNumByUGroupID(req, resp)
			case "getNormalLogsAnalysis":
				resp = node.getNormalLogsAnalysis(req, resp)
			case "getWarningLogsAnalysis":
				resp = node.getWarningLogsAnalysis(req, resp)
			case "getNormalLogsAnalysisByUGroupID":
				resp = node.getNormalLogsAnalysisByUGroupID(req, resp)
			case "getWarningLogsAnalysisByUGroupID":
				resp = node.getWarningLogsAnalysisByUGroupID(req, resp)
			case "getExtranetLogsAnalysisByUser":
				resp = node.getExtranetLogsAnalysisByUser(req, resp)
			case "getExtranetLogsAnalysisByWebsite":
				resp = node.getExtranetLogsAnalysisByWebsite(req, resp)
			case "getExtranetLogsAnalysisByUserAndUGroupID":
				resp = node.getExtranetLogsAnalysisByUserAndUGroupID(req, resp)
			case "getExtranetLogsAnalysisByWebsiteAndUGroupID":
				resp = node.getExtranetLogsAnalysisByWebsiteAndUGroupID(req, resp)
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

type ResponseGenerateCert struct {
	Name        string // 用户名
	KeyParam    MetaData.KeyParam
	Passwd      string // 手机号
	Invitation  string // 激活码
	Email       string // 邮箱信息
	Prikey      string // 设备信息
	Certificate string // 证书
	Pubkey      string // 公钥
	Cert        cert.Certificate
}

// IdentityRegistryforVPN 身份注册
//
// @Description: 提供给VPN管理后台的身份注册接口，该方法注册的身份无需管理员审核，直接生效
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) IdentityRegistryforVPN(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var id MetaData.Identity
	err := json.Unmarshal(res.Parameters, &id)
	// 解析身份
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "parse identity fail"
		common.Logger.Error("parse identity fail")
		return resp
	}
	// 验证参数
	if id.IdentityIdentifier == "" || id.Pubkey == "" || id.Passwd == "" || id.PrikeyEncrypted == "" {
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

	if node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
		common.Logger.Error("数据库已经存在该身份标识，注册失败", id.IdentityIdentifier)
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "数据库已经存在该身份标识"
		node.RegistryCache.Delete(id.IdentityIdentifier)
		return resp
	} else if node.mongo.HasIdentityData("pubkey", id.Pubkey) {
		common.Logger.Error("用户公钥重复，注册失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "用户公钥重复，注册失败"
		node.RegistryCache.Delete(id.IdentityIdentifier)
		return resp
	} else {
		var transaction MetaData.Identity
		transaction.Type = "identity-act"
		transaction.Command = "Registry"
		transaction.IdentityIdentifier = id.IdentityIdentifier
		transaction.KeyParam = MetaData.KeyParam{0, 0}
		transaction.Pubkey = id.Pubkey
		transaction.Passwd = id.Passwd
		transaction.PrikeyEncrypted = id.PrikeyEncrypted
		transaction.Timestamp = time.Now().Format("2006-01-02 15:04:05")
		transaction.IsValid = code.VALID
		transaction.IPIdentifier = id.IPIdentifier
		transaction.ModifyRecords = append(transaction.ModifyRecords, MetaData.ModifyRecord{Type: "identity-act",
			Command: "Registry", Timestamp: time.Now().Format("2006-01-02 15:04:05")})

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
			common.Logger.Error("证书签发失败：", err)
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "身份证书签发失败"
			node.RegistryCache.Delete(id.IdentityIdentifier)
		} else {
			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			transaction.Cert = c
			resp.Code = code.SUCCESS

			common.Logger.Info("身份申请注册中")
			go node.txPool.PushbackTransaction(transactionHeader, &transaction)
			node.registryList[transaction.Pubkey] = node.mongo.Height
			node.RegistryCache.Set(id.IdentityIdentifier, &transaction, 3600*time.Second)

			i := transaction.ParseBCIdentityToCommon()
			err = node.network.Keychain.SaveIdentity(&i, true)
			data, err := i.Dump("pkusz123456")
			if err != nil {
				common.Logger.Error("身份解析失败：", err)
				resp.Code = code.BAD_REQUEST
				resp.ErrorMsg = "身份解析失败"
			}
			resp.Data = data
		}
	}
	return resp
}

// IdentityRevokeRegistryForVMS 身份注册
//
// @Description: 提供给VMS的撤销身份注册接口
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) IdentityRevokeRegistryForVMS(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
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
		if node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
			// identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
			var transaction MetaData.Identity
			transaction.Type = "identity-act"
			transaction.Command = "DestroyByIdentityIdentifier"
			transaction.IdentityIdentifier = id.IdentityIdentifier

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			i := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
			flag, err := node.network.Keychain.DeleteIdentityByName(transaction.IdentityIdentifier, i.Passwd)
			if err != nil {
				common.Logger.Error(err)
			} else if flag == true {
				common.Logger.Info("sqlite删除身份成功")
			} else {
				common.Logger.Info("sqlite删除身份失败")
			}

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

// GetAllIdentityAllInf 获取所有身份
//
// @Description:
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) GetAllIdentity(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	identities := node.mongo.GetAllIdentityFromDatabase()
	data, err := json.Marshal(identities)
	if err != nil {
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "获取失败"
	}
	resp.Code = code.SUCCESS
	resp.Data = data
	return resp
}

type User struct {
	ID                int    // ID
	Name              string // 用户名
	Password          string // 用户密码
	Phone             string // 手机号
	Invitation        string // 激活码
	Email             string // 邮箱信息
	DeviceInfo        string // 设备信息
	Certificate       string // 证书
	Pubkey            string // 公钥
	Signature         []byte // 签名
	IsRevoked         int    // 是否被封禁
	UGroupID          int
	TimeStamp         string // 时间戳
	MaxMachine        int    // 最大设备数量
	CurMachine        int    // 当前设备数量
	LastMachineUpdate string //机器上次加入的时间
}

func (node *Node) UploadPhone(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var users []User
	err := json.Unmarshal(res.Parameters, &users)
	if err != nil {
		common.Logger.Error("上传数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "上传数据解析失败"
		return resp
	}
	for _, user := range users {
		if user.Name == "" || user.Phone == "" {
			common.Logger.Error("缺少必要字段")
			resp.Code = code.BAD_REQUEST
			resp.ErrorMsg = "缺少必要字段"
			return resp
		} else if !node.mongo.HasIdentityData("identityidentifier", user.Name) {
			common.Logger.Error("数据库不存在该身份标识，上传失败", user.Name)
			continue
		} else {
			Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", user.Name)

			var transaction MetaData.Identity
			transaction = Identity
			transaction.Type = "identity-act"
			transaction.Command = "UploadPhone"
			transaction.IdentityIdentifier = user.Name
			transaction.Phone = user.Phone

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			go node.txPool.PushbackTransaction(transactionHeader, &transaction)

			i := transaction.ParseBCIdentityToCommon()
			err := node.network.Keychain.SaveIdentity(&i, true)
			if err != nil {
				common.Logger.Error(err)
			}
			common.Logger.Info(transaction.IdentityIdentifier, "开始上传手机号: ", transaction.Phone)
		}
	}
	resp.Code = code.SUCCESS
	resp.Data = nil
	return resp
}

//// IdentityAuthentication TODO 加上打印
//func (node *Node) IdentityAuthentication(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
//	var id MetaData.Identity
//	err := json.Unmarshal(res.Parameters, &id)
//	// 解析身份
//	if err != nil {
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "身份解析失败"
//		// TODO 加上打印 如下所示 最好用英文
//		common.Logger.Error("parse identity fail")
//		return resp
//	}
//	// 验证参数
//	if id.IdentityIdentifier == "" || id.Pubkey == "" || id.Passwd == "" || id.Cert == "" ||
//		id.KeyParam == (MetaData.KeyParam{}) || id.Timestamp == "" || id.IPIdentifier == "" {
//		common.Logger.Error("less parameter")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "less parameter"
//		return resp
//	}
//	// var response CommonResponse
//	// 验证不更新修改记录
//	// node.mongo.UpdateIdentityModifyRecordsforAuthentication(id)
//
//	// 查询是否存在
//	if !node.mongo.HasIdentityData("identityidentifier", id.IdentityIdentifier) {
//		common.Logger.Error("数据库不存在该身份标识，认证失败", id.IdentityIdentifier)
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "数据库不存在该身份标识"
//		return resp
//	}
//	// 如果存在的话 取出对应身份 和 root身份
//	identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", id.IdentityIdentifier)
//	root := node.mongo.GetOneIdentityFromDatabase("identityidentifier", "root")
//	// 从root身份中取出证书
//	Ca := cert.Certificate{}
//	_ = Ca.FromPem(root.Cert, []byte(root.Passwd), minsecurity.SM4ECB)
//	// 对比两者身份是否一致
//	if id.Passwd != identity.Passwd || id.Timestamp != identity.Timestamp {
//		common.Logger.Error("身份注册信息不匹配")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "身份信息不匹配，认证失败"
//		return resp
//	}
//	if identity.IsValid == code.INVALID {
//		common.Logger.Error("该身份不可用")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "该身份不可用"
//		return resp
//	}
//	if id.KeyParam.SignatureAlgorithm == MetaData.SM2WithSM3 {
//		Cert := cert.Certificate{}
//		err := Cert.FromPem(id.Cert, []byte(identity.Passwd), minsecurity.SM4ECB)
//		if err != nil {
//			resp.Code = code.BAD_REQUEST
//			resp.ErrorMsg = "证书解析失败"
//			return resp
//		}
//		flag, err := cert.Verify(Cert, Ca)
//		if !flag || err != nil {
//			resp.Code = code.BAD_REQUEST
//			resp.ErrorMsg = "证书认证失败"
//			return resp
//		}
//		resp.Code = code.SUCCESS
//		resp.Data = nil
//		return resp
//	} else {
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "未知的签名算法"
//		common.Logger.Error("unknown signature algorithm")
//		return resp
//	}
//}

type logPool struct {
	logChan chan interface{}
	logPool sync.Pool
}

//var nLogPool = newLogPool(func() interface{} {
//	return network.GetBCSSLConn()
//})
//
//var wLogPool = newLogPool(func() interface{} {
//	return network.GetBCSSLConn()
//})

func (node *Node) UploadUserLog(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	log := node.UserLogPool.logPool.Get().(*MetaData.UserLog)
	err := json.Unmarshal(res.Parameters, &log)
	if err != nil {
		common.Logger.Error("日志数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "日志数据解析失败"
		return resp
	} else if log.Data == "" || log.Permission == "" || log.Source == "" || log.Name == "" ||
		log.Timestamp == "" || log.Level == 0 || log.IdentityIdentifier == "" || log.UGroupID == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	} else if !node.mongo.HasIdentityData("identityidentifier", log.IdentityIdentifier) {
		common.Logger.Error("数据库不存在该身份标识，认证失败", log.IdentityIdentifier)
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "数据库不存在该身份标识"
		return resp
	}
	node.UserLogPool.logPool.Put(log)

	transaction := node.UserLogPool.logPool.Get().(*MetaData.UserLog)
	// node.mongo.UpdateIdentityModifyRecordsforUploadUserLog(log)
	if log.Level == code.NORMAL {
		transaction.Data = log.Data
		transaction.Permission = log.Permission
		transaction.IdentityIdentifier = log.IdentityIdentifier
		transaction.Source = log.Source
		transaction.Name = log.Name
		transaction.Timestamp = log.Timestamp
		transaction.Level = log.Level
		transaction.Command = "UploadNormalUserLog"
		transaction.UGroupID = log.UGroupID

		transaction.Protocol = log.Protocol
		transaction.Destination = log.Destination
		transaction.WebSite = log.WebSite
		transaction.FilterWebSite = log.FilterWebSite
		transaction.IsInner = log.IsInner
	} else {
		transaction.Data = log.Data
		transaction.Permission = log.Permission
		transaction.IdentityIdentifier = log.IdentityIdentifier
		transaction.Source = log.Source
		transaction.Name = log.Name
		transaction.Timestamp = log.Timestamp
		transaction.Level = log.Level
		transaction.Command = "UploadWarningUserLog"
		transaction.UGroupID = log.UGroupID

		transaction.Protocol = log.Protocol
		transaction.Destination = log.Destination
		transaction.WebSite = log.WebSite
		transaction.FilterWebSite = log.FilterWebSite
		transaction.WarnInfo = log.WarnInfo
		transaction.IsInner = log.IsInner
	}

	node.UserLogPool.logChan <- transaction
	node.UserLogPool.logPool.Put(transaction)
	//var transactionHeader MetaData.TransactionHeader
	//transactionHeader.TXType = MetaData.UserLogOperation
	//go node.txPool.PushbackTransaction(transactionHeader, &transaction)

	common.Logger.Info(log.IdentityIdentifier, "日志已加入到上传队列")
	resp.Code = code.SUCCESS
	resp.Data = nil

	return resp
}

func (node *Node) StartUploadUserLogServer() error {
	defer func() {
		if err := recover(); err != nil {
			common.Logger.Error("panic when program execute,err:", err)
			debug.PrintStack()
		}
	}()

	for {
		select {
		case log := <-node.UserLogPool.logChan:
			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.UserLogOperation
			common.Logger.Info(log.(*MetaData.UserLog).IdentityIdentifier, " 日志正在申请上传")
			r := node.txPool.PushbackTransaction(transactionHeader, log.(*MetaData.UserLog))
			if r == -1 {
				return errors.New("日志放入事务池失败")
			}
		}
	}
}

type PageUserlogRequest struct {
	UserName  string
	UGroupID  int
	PageSize  int
	PageNo    int
	BeginTime string
	EndTime   string
}

type PageUserlogRespond struct {
	Logs  []MetaData.UserLog
	Count int
}

func (node *Node) GetAllNormalLogsByTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetNormalLogsByTimestampFromDatabase(start, end)
	total := node.mongo.GetNormalLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetPageNormalLogsByTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.BeginTime == "" || request.EndTime == "" || request.PageSize == 0 || request.PageNo == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	pageSize := request.PageSize
	pageNum := request.PageNo
	skip := pageSize * (pageNum - 1)
	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetPageNormalLogsByTimestampFromDatabase(start, end, skip, pageSize)
	total := node.mongo.GetPageNormalLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetAllWarningLogsByTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetAllWarningLogsByTimestampFromDatabase(start, end)
	total := node.mongo.GetAllWarningLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetPageWarningLogsByTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.BeginTime == "" || request.EndTime == "" || request.PageSize == 0 || request.PageNo == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	pageSize := request.PageSize
	pageNum := request.PageNo
	skip := pageSize * (pageNum - 1)
	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetPageWarningLogsByTimestampFromDatabase(start, end, skip, pageSize)
	total := node.mongo.GetPageWarningLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetAllNormalLogsByUGroupIDAndTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetAllNormalLogsByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end)
	total := node.mongo.GetAllNormalLogsCountByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetPageNormalLogsByUGroupIDAndTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" || request.PageSize == 0 || request.PageNo == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	pageSize := request.PageSize
	pageNum := request.PageNo
	skip := pageSize * (pageNum - 1)
	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetPageNormalLogsByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end, skip, pageSize)
	total := node.mongo.GetPageNormalLogsCountByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetAllWarningLogsByUGroupIDAndTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetAllWarningLogsByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end)
	total := node.mongo.GetAllWarningLogsCountByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetPageWarningLogsByUGroupIDAndTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" || request.PageSize == 0 || request.PageNo == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	pageSize := request.PageSize
	pageNum := request.PageNo
	skip := pageSize * (pageNum - 1)
	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetPageWarningLogsByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end, skip, pageSize)
	total := node.mongo.GetPageWarningLogsCountByGroupIDAndTimestampFromDatabase(request.UGroupID, start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetPageNormalLogsByUserNameAndTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UserName == "" || request.BeginTime == "" || request.EndTime == "" || request.PageSize == 0 || request.PageNo == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	pageSize := request.PageSize
	pageNum := request.PageNo
	skip := pageSize * (pageNum - 1)
	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetPageNormalLogsByUserNameAndTimestampFromDatabase(request.UserName, start, end, skip, pageSize)
	total := node.mongo.GetPageNormalLogsCountByUserNameAndTimestampFromDatabase(request.UserName, start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetPageWarningLogsByUserNameAndTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UserName == "" || request.BeginTime == "" || request.EndTime == "" || request.PageSize == 0 || request.PageNo == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	pageSize := request.PageSize
	pageNum := request.PageNo
	skip := pageSize * (pageNum - 1)
	start := request.BeginTime
	end := request.EndTime
	logs := node.mongo.GetPageWarningLogsByUserNameAndTimestampFromDatabase(request.UserName, start, end, skip, pageSize)
	total := node.mongo.GetPageWarningLogsCountByUserNameAndTimestampFromDatabase(request.UserName, start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}
	data, err := json.Marshal(logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

type UserlogAnalysisRequest struct {
	Num       int
	UGroupID  int
	BeginTime string
	EndTime   string
}

type UserlogAnalysisRespond struct {
	Analysis []int
}

func (node *Node) GetNormalLogsAnalysis(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = UserlogAnalysisRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	dur := request.Num

	analysis := node.mongo.GetNormalLogsAnalysisFromDatabase(start, end, dur)
	respond := UserlogAnalysisRespond{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetWarningLogsAnalysis(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = UserlogAnalysisRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	dur := request.Num

	analysis := node.mongo.GetWarningLogsAnalysisFromDatabase(start, end, dur)
	respond := UserlogAnalysisRespond{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetNormalLogsAnalysisByUGroupID(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = UserlogAnalysisRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	uid := request.UGroupID
	dur := request.Num

	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseByUGroupID(start, end, dur, uid)
	respond := UserlogAnalysisRespond{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) GetWarningLogsAnalysisByUGroupID(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = UserlogAnalysisRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	uid := request.UGroupID
	dur := request.Num

	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseByUGroupID(start, end, dur, uid)
	respond := UserlogAnalysisRespond{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

type LogNum struct {
	NormLogNum int
	WarnLogNum int
}

func (node *Node) getUGroupLogNumByUGroupID(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = PageUserlogRequest{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UGroupID == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}

	normLogNum := node.mongo.GetAllNormalLogsCountByGroupIDFromDatabase(request.UGroupID)
	warnLogNum := node.mongo.GetAllWarningLogsCountByGroupIDFromDatabase(request.UGroupID)

	logdata := LogNum{NormLogNum: normLogNum, WarnLogNum: warnLogNum}
	data, err := json.Marshal(&logdata)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

type GetDataAnalysis struct {
	BeginTime string `validate:"required"`
	EndTime   string `validate:"required"`
	Num       int    `validate:"required"` // 天数
}
type result struct {
	Analysis []int
}

func (node *Node) getNormalLogsAnalysis(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = GetDataAnalysis{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	dur := request.Num

	var analysis []int

	analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseDaysOrMonth(start, end, dur)
	/*
		if dur >= 28 || dur <= 31 {
			analysis = node.mongo.GetNormalLogsAnalysisFromDatabase(start, end, dur)
		} else if dur == 12 {
			analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonth()
		}
	*/

	common.Logger.Info("analysis:", analysis)
	respond := result{Analysis: analysis}
	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}
	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) getWarningLogsAnalysis(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = GetDataAnalysis{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	dur := request.Num

	var analysis []int
	analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseDaysOrMonth(start, end, dur)
	/*
		if dur >= 28 || dur <= 31 {
			analysis = node.mongo.GetWarningLogsAnalysisFromDatabase(start, end, dur)
		} else if dur == 12 {
			analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonth()
		}
	*/
	respond := result{Analysis: analysis}
	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}
	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

type GetUGroupDataAnalysis struct {
	UGroupID  int    `validate:"required"` // 需要获取数据的用户组
	BeginTime string `validate:"required"` // 获取日志的起始时间
	EndTime   string `validate:"required"` // 获取日志的结束时间
	Num       int    `validate:"required"` // 天数
}

func (node *Node) getNormalLogsAnalysisByUGroupID(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = GetUGroupDataAnalysis{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	uid := request.UGroupID
	dur := request.Num
	var analysis []int
	analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseDaysOrMonthByUGroupID(start, end, dur, uid)
	/*
		if dur >= 28 || dur <= 31 {
			analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseByUGroupID(start, end, dur, uid)
		} else if dur == 12 {
			analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID()
		}
	*/
	respond := result{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) getWarningLogsAnalysisByUGroupID(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = GetUGroupDataAnalysis{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.Num == 0 || request.UGroupID == 0 || request.BeginTime == "" || request.EndTime == "" {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	start := request.BeginTime
	end := request.EndTime
	uid := request.UGroupID
	dur := request.Num

	var analysis []int
	analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseDaysOrMonthByUGroupID(start, end, dur, uid)
	/*
		if dur >= 28 || dur <= 31 {
			analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseByUGroupID(start, end, dur, uid)
		} else if dur == 12 {
			analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonth()
		}
	*/
	respond := result{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

type ExtranetLogsAnalysisResponse struct {
	Analysis map[string]int
}

func (node *Node) getExtranetLogsAnalysisByUser(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	analysis, ok := node.UserlogAnalysis.Load("User")

	//analysis, err := node.mongo.GetLogsAnalysisByUser(typ)
	if !ok {
		common.Logger.Error("请求ExtranetLogsAnalysisByUser失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求ExtranetLogsAnalysisByUser失败"
		return resp
	}

	common.Logger.Info("getExtranetLogsAnalysisByUser:", analysis)

	respond := ExtranetLogsAnalysisResponse{Analysis: analysis.(map[string]int)}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) getExtranetLogsAnalysisByWebsite(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	analysis, ok := node.UserlogAnalysis.Load("Website")

	//analysis, err := node.mongo.GetLogsAnalysisByUser(typ)
	if !ok {
		common.Logger.Error("请求ExtranetLogsAnalysisByWebsite失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求ExtranetLogsAnalysisByWebsite失败"
		return resp
	}

	common.Logger.Info("getExtranetLogsAnalysisByWebSite:", analysis)

	respond := ExtranetLogsAnalysisResponse{Analysis: analysis.(map[string]int)}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

type GetUGroupExtranetLogsAnalysis struct {
	UGroupID int `validate:"required"` // 需要获取数据的用户组
}

func (node *Node) getExtranetLogsAnalysisByUserAndUGroupID(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = GetUGroupExtranetLogsAnalysis{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UGroupID == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	analysis, err := node.mongo.GetExtranetLogsAnalysisByUserAndUGroupID(request.UGroupID, node.config.StartTime)
	if err != nil {
		common.Logger.Error("请求ExtranetLogsAnalysisByUserAndUGroupID失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求ExtranetLogsAnalysisByUserAndUGroupID失败"
		return resp
	}

	common.Logger.Info("getExtranetLogsAnalysisByUserAndUGroupID:", analysis)

	respond := ExtranetLogsAnalysisResponse{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) getExtranetLogsAnalysisByWebsiteAndUGroupID(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
	var request = GetUGroupExtranetLogsAnalysis{}
	err := json.Unmarshal(res.Parameters, &request)
	if err != nil {
		common.Logger.Error("请求数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求数据解析失败"
		return resp
	}

	if request.UGroupID == 0 {
		common.Logger.Error("缺少必要字段")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "缺少必要字段"
		return resp
	}
	analysis, err := node.mongo.GetExtranetLogsAnalysisByWebsiteAndUGroupID(request.UGroupID, node.config.StartTime)
	if err != nil {
		common.Logger.Error("请求ExtranetLogsAnalysisByWebsiteAndUGroupID失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "请求ExtranetLogsAnalysisByWebsiteAndUGroupID失败"
		return resp
	}

	common.Logger.Info("getExtranetLogsAnalysisByWebsiteAndUGroupID:", analysis)

	respond := ExtranetLogsAnalysisResponse{Analysis: analysis}

	data, err := json.Marshal(respond)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		resp.Code = code.BAD_REQUEST
		resp.ErrorMsg = "回复数据解析失败"
		return resp
	}

	resp.Code = code.SUCCESS
	resp.Data = data

	return resp
}

func (node *Node) StartLogsAnalysisServer() error {
	defer func() {
		if err := recover(); err != nil {
			common.Logger.Error("panic when program execute,err:", err)
			debug.PrintStack()
		}
	}()

	timeTickerChan := time.Tick(time.Minute * 1)
	for {
		fmt.Println(time.Now().Format("2006-01-02 15:04:05"), " 开始进行日志分析")
		analysis1, err := node.mongo.GetExtranetLogsAnalysisByUser(node.config.StartTime)
		if err != nil {
			common.Logger.Error(err)
			return err
		}
		node.UserlogAnalysis.Store("User", analysis1)

		analysis2, err := node.mongo.GetExtranetLogsAnalysisByWebsite(node.config.StartTime)
		if err != nil {
			common.Logger.Error(err)
			return err
		}
		node.UserlogAnalysis.Store("Website", analysis2)
		<-timeTickerChan
	}
}

type UserName struct {
	Name string `validate:"required"` // 用户名字信息
}

func (node *Node) SendRemoveUserToVMS(identityidentifier string) error {
	// 使用同一个变量
	var request = network.NewNetRequest()
	request.Type = "user"
	request.Command = "deleteUserByName"

	if strings.HasPrefix(identityidentifier, "/") {
		identityidentifier = identityidentifier[1:]
	}

	data, _ := json.Marshal(UserName{
		Name: identityidentifier,
	})
	request.Parameters = data

	conn := node.network.GetVMSSSLConn()

	err := network.SendRequest(request, conn)
	if err != nil {
		common.Logger.Error("fail to send request to vms")
		_ = conn.Close()
		return err
	}
	res, err := network.GetResponse(conn)
	if err != nil {
		common.Logger.Error("fail to get response from vms,error:", err.Error())
		_ = conn.Close()
		return err
	}
	if res.Code == code.SUCCESS {
		common.Logger.Info("remove vpn user success")
		_ = conn.Close()
		return nil
	} else {
		common.Logger.Error("remove vpn user fail ,error:", res.ErrorMsg)
		_ = conn.Close()
		return errors.New(res.ErrorMsg)
	}
}

//func (node *Blockchain) HandleVPNMGMTMessage1(data []byte, conn net.Conn) {
//
//	defer func() {
//		if r := recover(); r != nil {
//			fmt.Printf("捕获到的错误：%s\n", r)
//			fmt.Printf("堆栈信息：%s\n", string(debug.Stack()))
//		}
//	}()
//
//	var res map[string]interface{}
//	err := json.Unmarshal(data, &res)
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	fmt.Println("解析出来的数据为:", res)
//
//	if res["Type"] == "Setup" {
//		switch res["Command"] {
//		case "SetUpConnection":
//			node.SetUpConnectionWithVPNMGMT(res, conn)
//		}
//	}
//
//	if res["IsEnc"] == "true" {
//		sessionId := res["SessionId"].(string)
//		if node.SessionCache.Get(sessionId) == nil || node.SessionCache.Get(sessionId).Expired() {
//			fmt.Println("SessionID 不存在或者过期")
//			data, err := encoding.Encode([]byte("重新建立连接"))
//			if err != nil {
//				fmt.Println("encode msg failed, err:", err)
//			}
//			_, err = conn.Write(data)
//			if err != nil {
//				fmt.Println("send msg failed, err:", err)
//			}
//		}
//		key := node.SessionCache.Get(sessionId).Value().(string)
//		if node.secretKeyforVPNMGMT == "" {
//			fmt.Println("密钥为空")
//			data, err := encoding.Encode([]byte("重新建立连接"))
//			if err != nil {
//				fmt.Println("encode msg failed, err:", err)
//			}
//			_, err = conn.Write(data)
//			if err != nil {
//				fmt.Println("send msg failed, err:", err)
//			}
//		}
//		node.SessionCache.Set(sessionId, key, 10*time.Minute)
//		var request map[string]interface{}
//
//		databyte, err := base64.StdEncoding.DecodeString(res["Data"].(string))
//		if err != nil {
//			common.Logger.Fatal("base64 decoding failed, err:", err)
//		}
//		data, err := keymanager.SM4Decrypt(node.secretKeyforVPNMGMT, databyte)
//		if err != nil {
//			common.Logger.Fatal("sm4 decrypt failed, err:", err)
//		}
//		if string(data) != "" {
//			err = json.Unmarshal(data, &request)
//			if err != nil {
//				fmt.Println(err)
//				return
//			}
//		}
//
//		request["Type"] = res["Type"].(string)
//		request["Command"] = res["Command"].(string)
//		request["SessionId"] = res["SessionId"].(string)
//		request["IsEnc"] = res["IsEnc"].(string)
//
//		res = request
//		fmt.Println("收到的后台数据为:", res)
//	}
//
//	if res["Type"] == nil || res["Command"] == nil {
//		return
//	}
//
//	if res["Type"] == "log" {
//		switch res["Command"] {
//		case "Login":
//			node.Login(res, conn)
//		}
//	}
//
//	if res["Type"] == "identity-act" {
//		switch res["Command"] {
//		case "Authentication":
//			node.IdentityAuthentication(res, conn)
//		}
//	}
//	if res["Type"] == "log" {
//		switch res["Command"] {
//		case "UploadUserLog":
//			node.UploadUserLog(res, conn)
//		}
//	}
//}
//
///*建立连接 ，进行加密通信*/
//func (node *Blockchain) SetUpConnectionWithVPNMGMT(res map[string]interface{}, conn net.Conn) {
//	fmt.Println("开始建立连接")
//	if res["Data"] == nil {
//		resp := Network.ResponseMsg{Code: 400, Message: "数据为空", Data: nil}
//		data, err := json.Marshal(resp)
//		if err != nil {
//			fmt.Println(err)
//		}
//		Network.SendResponse(conn, data, "")
//		return
//	} //数据为空 报错 发送400
//	sourceData := res["Data"].(string)
//	decodeContent, err := base64.StdEncoding.DecodeString(sourceData) //进行base64解码
//	if err != nil {
//		fmt.Println("decode failed, ", err)
//		resp := Network.ResponseMsg{Code: 400, Message: "", Data: nil}
//		data, _ := json.Marshal(resp)
//		Network.SendResponse(conn, data, "")
//		return
//	}
//
//	//非对称加密解密
//	key := keymanager.KeyManager{}
//	key.Init()
//	key.SetPriKey(node.network.SSLPrikey)
//	key.SetPubkey(node.network.SSLPubkey)
//	if key.IsOnCurve() == false {
//		common.Logger.Fatal("Server creates failed..., because the private key and public key don't match.")
//	}
//	result, err := key.Decrypt(string(decodeContent))
//
//	if result == nil || err != nil {
//		fmt.Println(err)
//		resp := Network.ResponseMsg{Code: 400, Message: "", Data: nil}
//		data, _ := json.Marshal(resp)
//		Network.SendResponse(conn, data, "")
//		return
//	}
//
//	fmt.Println("解析出来的密钥为", string(result))
//
//	var request map[string]interface{}
//	err = json.Unmarshal(result, &request)
//	if err != nil {
//		fmt.Println(err)
//		resp := Network.ResponseMsg{Code: 400, Message: "", Data: nil}
//		data, _ := json.Marshal(resp)
//		Network.SendResponse(conn, data, "")
//		return
//	}
//	if request["SecretKey"] == nil {
//		resp := Network.ResponseMsg{Code: 400, Message: "", Data: nil}
//		data, _ := json.Marshal(resp)
//		Network.SendResponse(conn, data, "")
//		return
//	}
//
//	secretKey := request["SecretKey"].(string)
//	u1, err := uuid.NewUUID() //生成uuid
//	if err != nil {
//		fmt.Println(err)
//		resp := Network.ResponseMsg{Code: 400, Message: "", Data: nil}
//		data, _ := json.Marshal(resp)
//		Network.SendResponse(conn, data, "")
//		return
//	}
//	if node.SessionCache.Get(u1.String()) != nil && !node.SessionCache.Get(u1.String()).Expired() {
//		fmt.Println("该SessionId已经存在 而且没有过期")
//		resp := Network.ResponseMsg{Code: 400, Message: "", Data: nil}
//		data, _ := json.Marshal(resp)
//		Network.SendResponse(conn, data, "")
//		return
//	}
//	node.SessionCache.Set(u1.String(), secretKey, 10*time.Minute)
//	node.secretKeyforVPNMGMT = secretKey
//	fmt.Println("对称密钥建立成功,SessionId:", u1.String(), ", key", secretKey)
//	msg, _ := keymanager.SM4Encrypt(secretKey, []byte(u1.String()))
//	encode := base64.RawURLEncoding.EncodeToString(msg)
//	resp := Network.ResponseMsg{Code: 200, Message: encode}
//	data, _ := json.Marshal(resp)
//	Network.SendResponse(conn, data, "")
//	return
//}

//func (node *Node) GetPageLogByIdentityIdentifier(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
//	var request = PageUserlogRequest{Start: "", End: "", PageSize: 0, PageNum: 0}
//	err := json.Unmarshal(res.Parameters, &request)
//	if err != nil {
//		common.Logger.Error("请求数据解析失败")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "请求数据解析失败"
//		return resp
//	}
//
//	if request.IdentityIdentifier == "" {
//		common.Logger.Error("缺少必要字段")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "缺少必要字段"
//		return resp
//	}
//
//	pageSize := request.PageSize
//	pageNum := request.PageNum
//	skip := pageSize * (pageNum - 1)
//	logs := node.mongo.GetPageLogsByIdentityIdentifierFromDatabase(request.IdentityIdentifier, skip, pageSize)
//	total := node.mongo.GetPageLogsCountByIdentityIdentifierFromDatabase(request.IdentityIdentifier)
//
//	logdata := PageUserlogRespond{Logs: logs, Total: total}
//	data, err := json.Marshal(logdata)
//	if err != nil {
//		common.Logger.Error("回复数据解析失败")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "回复数据解析失败"
//		return resp
//	}
//
//	resp.Code = code.SUCCESS
//	resp.Data = data
//
//	return resp
//}

//func (node *Node) GetPageLogsByTimestamp(res *network.NetRequest, resp *network.NetResponse) *network.NetResponse {
//	var request = PageUserlogRequest{Start: "", End: "", PageSize: 0, PageNum: 0}
//	err := json.Unmarshal(res.Parameters, &request)
//	if err != nil {
//		common.Logger.Error("请求数据解析失败")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "请求数据解析失败"
//		return resp
//	}
//
//	if request.Start == "" || request.End == "" || request.PageSize == 0 || request.PageNum == 0 {
//		common.Logger.Error("缺少必要字段")
//		resp.Code = code.BAD_REQUEST
//		resp.ErrorMsg = "缺少必要字段"
//		return resp
//	}
//	start := request.Start
//	end := request.End
//	pageSize := request.PageSize
//	pageNUm := request.PageNum
//	skip := pageSize * (pageNUm - 1)
//
//	logs := node.mongo.GetPageLogsByRangeTimeFromDatabase(start, end, skip, pageSize)
//	total := node.mongo.GetPageLogsCountByRangeTimeFromDatabase(start, end)
//
//	var response CommonResponse
//	response.Code = code.SUCCESS
//	response.Message = strconv.Itoa(total)
//	response.Data = logs
//
//	return resp
//}
