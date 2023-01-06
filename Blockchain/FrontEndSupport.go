/**
 * @Author: xzw
 * @Description:
 * @Version: 1.0.0
 * @Date: 2021/5/31 下午5:00
 * @Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
 */

package Node

import (
	"MIS-BC/MetaData"
	"MIS-BC/Network"
	"MIS-BC/Network/network/encoding"
	"MIS-BC/common"
	"MIS-BC/security/code"
	"MIS-BC/security/keymanager"
	"MIS-BC/utils"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/patrickmn/go-cache"
	"math/rand"
	"minlib/minsecurity"
	"minlib/minsecurity/crypto/cert"
	"minlib/minsecurity/crypto/sm2"
	"net"
	"runtime/debug"
	"strconv"
	"time"
)

// 区块链后台给管理员前端的通用回复
// @Description:
//  1. Code: 状态码，见"MIS-BC/security/code"
//  2. Message: 回复信息
//  3. Data: 返回的数据
//

type CommonResponse struct {
	Code    int
	Message string
	Data    interface{}
}

//type IdentityImmutableInf struct {
//	IdentityIdentifier string
//	Pubkey  		   string
//	Cert    		   string
//	Timestamp    	   string
//	KeyParam		   MetaData.KeyParam
//}

//type IdentityMutableInf struct {
//	IPIdentifier    string
//	Passwd    		string
//	ModifyRecords	[]MetaData.ModifyRecord
//}

// 分页身份信息
// @Description:
//  1. 区块链后台给管理员前端的回复的分页身份信息
//
type PageIdentityInf struct {
	Identities []MetaData.Identity
	Total      int
}

// 分页区块信息
// @Description:
//  1. 区块链后台给管理员前端的回复的分页区块信息
//
type PageBlockGroupInf struct {
	Blockgroups []MetaData.BlockGroup
	Total       int
}

type TransactionforCRS struct {
	TransactionType int
	TransactionNum  string
	Transaction     interface{}
}

// 分页交易信息
// @Description:
//  1. 区块链后台给管理员前端的回复的分页交易信息
//
type PageTransactionInf struct {
	Transactions []TransactionforCRS
	Total        int
}

//type PageIdentityMutableInf struct {
//	Identities []IdentityMutableInf
//	Total int
//}

//type PageIdentityImmutableInf struct {
//	Identities []IdentityMutableInf
//	Total int
//}

//type GetLogMsgResponse struct {
//	Code  int
//	Message string
//	LogTotal    int
//	Logs        []MetaData.UserLog
//}

// HandleFrontEndMessage 在收到前端的请求信息后调用该方法
//
// @Description:
// @receiver node
// @param data
// @param conn
//
func (node *Node) HandleFrontEndMessage(data []byte, conn net.Conn) {
	// 错误处理
	defer func() {
		if r := recover(); r != nil {
			common.Logger.Errorf("捕获到的错误：%s\n", r)
			common.Logger.Infof("堆栈信息：%s\n", string(debug.Stack()))
		}
	}()

	// 前端请求解析
	var res map[string]interface{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		common.Logger.Error(err)
		return
	}

	// 建立连接请求处理
	if res["Type"] == "Setup" {
		switch res["Command"] {
		case "SetUpConnection":
			node.SetUpConnection(res, conn)
		}
		return
	}
	if res["IsEnc"] == "true" {
		sessionId := res["SessionId"].(string)
		if _, ok := node.SessionCache.Get(sessionId); ok == false {
			common.Logger.Info("SessionID 不存在或者过期")
			resp := CommonResponse{Code: code.FORBIDDEN, Message: "重新建立连接", Data: nil}
			data, err := json.Marshal(resp)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, "")
			conn.Close()
			return
			//data, err := encoding.Encode([]byte("重新建立连接"))
			//if err != nil {
			//	common.Logger.Error("encode msg failed, err:", err)
			//}
			//_, err = conn.Write(data)
			//if err != nil {
			//	common.Logger.Error("send msg failed, err:", err)
			//}
			//// SessionId超时，断开连接
			// conn.Close()
		}
		// SessionId未超时，取出缓存中的对称密钥
		key, _ := node.SessionCache.Get(sessionId)
		if key == "" {
			common.Logger.Info("密钥为空")
			resp := CommonResponse{Code: code.FORBIDDEN, Message: "重新建立连接", Data: nil}
			data, err := json.Marshal(resp)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, "")
			conn.Close()
			return

			//common.Logger.Infof("密钥为空")
			//data, err := encoding.Encode([]byte("重新建立连接"))
			//if err != nil {
			//	common.Logger.Error("encode msg failed, err:", err)
			//}
			//_, err = conn.Write(data)
			//if err != nil {
			//	common.Logger.Error("send msg failed, err:", err)
			//}
			//// 对称密钥读取失败，断开连接
			//conn.Close()
		}
		// 更新SessionId有效期
		node.SessionCache.Set(sessionId, key, 10*time.Minute)

		request := make(map[string]interface{})
		if res["Data"] != nil {
			// Data部分是base64字符串，需解码
			databyte, err := base64.StdEncoding.DecodeString(res["Data"].(string))
			if err != nil {
				common.Logger.Error("base64 decoding failed, err:", err)
			}
			// 字节数据进行SM4解密
			data, err := keymanager.SM4Decrypt(key.(string), databyte)
			if err != nil {
				common.Logger.Error("sm4 decrypt failed, err:", err)
			}
			// 解密出来的如果是空字符串的处理
			if string(data) != "" {
				err = json.Unmarshal(data, &request)
				if err != nil {
					common.Logger.Error("json unmarshal failed, err:", err)
					return
				}
			}
		}
		request["Type"] = res["Type"].(string)
		request["Command"] = res["Command"].(string)
		request["SessionId"] = res["SessionId"].(string)
		request["IsEnc"] = res["IsEnc"].(string)
		request["Key"] = key.(string)
		res = request

		common.Logger.Info("收到的后台数据为:", res)
	} else if res["IsEnc"] == "false" {
		sessionId := res["SessionId"].(string)
		if _, ok := node.SessionCache.Get(sessionId); ok == false {
			common.Logger.Info("SessionID 不存在或者过期")
			data, err := encoding.Encode([]byte("重新建立连接"))
			if err != nil {
				common.Logger.Error("encode msg failed, err:", err)
			}
			_, err = conn.Write(data)
			if err != nil {
				common.Logger.Error("send msg failed, err:", err)
			}
			// SessionId超时，断开连接
			conn.Close()
		}
		// 更新SessionId有效期
		node.SessionCache.Set(sessionId, "", 10*time.Minute)

		request := make(map[string]interface{})
		if res["Data"] != nil {
			// Data部分是base64字符串，需解码
			databyte, err := base64.StdEncoding.DecodeString(res["Data"].(string))
			if err != nil {
				common.Logger.Error("base64 decoding failed, err:", err)
			}
			// 解密出来的如果是空字符串的处理
			if string(databyte) != "" {
				err = json.Unmarshal(data, &request)
				if err != nil {
					common.Logger.Error("json unmarshal failed, err:", err)
					return
				}
			}
		}
		request["Type"] = res["Type"].(string)
		request["Command"] = res["Command"].(string)
		request["SessionId"] = res["SessionId"].(string)
		request["IsEnc"] = res["IsEnc"].(string)
		res = request

		common.Logger.Info("收到的后台数据为:", res)
	}
	// Type和Command为空
	if res["Type"] == nil || res["Command"] == nil {
		common.Logger.Error("必要字段不足!")
		return
	} else if res["Type"] == "manager-act" { // manager-act类型操作
		switch res["Command"] {
		case "Login":
			node.Login(res, conn)
		case "LoginWithWeChat":
			node.LoginWithWeChat(res, conn)
		case "ResetValidation":
			node.ResetValidation(res, conn)
		}
		return
	} else if res["Type"] == "node" { // node类型操作
		switch res["Command"] {
		//case "GetTPSMsgFromServer":
		//	node.SendTPSMsgToFrontend(conn, request)
		case "GetBGMsgOfCertainHeightFromServer":
			node.SendBGMsgOfCertainHeightToFrontend(res, conn) // 查询指定高度的区块组信息
		case "GetBCNodeStatusMsgFromServer":
			node.SendBCNodeStatusToFrontend(res, conn) // 给前端回送区块链节点状态
		case "GetRolesProportion":
			node.GetRolesProportion(res, conn) // 各个节点(不同角色)的比例
		case "GetListButlernext":
			node.GetListButlernext(res, conn) // 分别获取所有的不同角色节点的信息
		case "GetListButler":
			node.GetListButler(res, conn) // 分别获取所有的不同角色节点的信息
		case "GetListCom":
			node.GetListCom(res, conn) // 分别获取所有的不同角色节点的信息
		case "GetStatusProportion":
			node.GetStatusProportion(res, conn) // 正常、异常节点的比例
		case "GetStatusNormalList":
			node.GetStatusNormalList(res, conn) //  正常节点列表
		case "GetStatusAbnormalList":
			node.GetStatusAbnormalList(res, conn) // 异常节点列表
		case "GetBlockInfByPage":
			node.GetBlockInfByPage(res, conn)

		case "GetOverviewInfo":
			node.getOverviewInfo(res, conn)
		case "GetTransactionAnalysis":
			node.getTransactionAnalysis(res, conn)
		case "GetLastBGsInfo":
			node.getLastBlocksInfo(res, conn)
		case "GetLastTransactionsInfo":
			node.getLastTransactionsInfo(res, conn)

		case "AgreeAddNewNode":
			node.AgreeAddNewNode(res, conn)
		case "RemoveNodeApply":
			node.RemoveNodeApply(res, conn)
		case "GetNodeListPrint":
			node.GetNodeListPrint(conn)
		case "QuitMyself":
			node.QuitMyself(conn)
		}
		return
	} else if res["Type"] == "identity-act" { // 普通身份类型操作
		switch res["Command"] {
		case "Registry":
			node.IdentityRegistry(res, conn)
		case "BindWeChat":
			node.BindWeChat(res, conn)
		case "UnboundWeChat":
			node.UnBindWeChat(res, conn)
		case "DestroyByIdentityIdentifier":
			node.IdentityDestroyByIdentityIdentifier(res, conn)
		case "ResetPassword":
			node.IdentityResetPassword(res, conn)
		case "CheckPassword":
			node.IdentityCheckPassword(res, conn)
		case "ResetIPIdentifier":
			node.IdentityResetIPIdentifier(res, conn)

		case "Authentication":
			node.IdentityAuthenticationforMIS(res, conn)
		case "GetValidIdentity":
			node.GetValidIdentityforMIS(res, conn)
		case "UploadEncryptedPrikey":
			node.UploadEncryptedPrikeyforMIS(res, conn)

		case "getAllIdentityAllInf":
			node.GetAllIdentityAllInf(res, conn)
		case "getAllIdentityAllInfByPage":
			node.GetAllIdentityAllInfByPage(res, conn)
		//case "getAllIdentityByPage":
		//	node.GetAllIdentityAllImmutableInfByPage(res, conn)
		//case "getAllIdentityImmutableInf":
		//	node.GetAllIdentityImmutableInf(res, conn)
		case "getOneIdentityInfByIdentityIdentifier":
			node.GetOneIdentityInfByIdentityIdentifier(res, conn)
		case "getOneIdentityPublicKey":
			node.GetOneIdentityPublicKey(res, conn)

		case "getAllPendingIdentity":
			node.GetAllPendingIdentity(res, conn)
		case "getAllPendingIdentityByPage":
			node.GetAllPendingIdentityByPage(res, conn)
		case "getAllCheckedIdentity":
			node.GetAllCheckedIdentity(res, conn)
		case "getAllCheckedIdentityByPage":
			node.GetAllCheckedIdentityByPage(res, conn)
		case "getAllDisabledIdentityByPage":
			node.GetAllDisabledIdentityByPage(res, conn)
		case "getAllAbledIdentityByPage":
			node.GetAllAbledIdentityByPage(res, conn)
		case "getAllWithoutCertIdentityByPage":
			node.GetAllWithoutCertIdentityByPage(res, conn)

		case "GetAllActionsByIdentityIdentifier":
			node.GetAllActionsByIdentityIdentifier(res, conn)
		case "GetAllActionsByIdentityIdentifierAndPage":
			node.GetAllActionsByIdentityIdentifierAndPage(res, conn)
		case "GetNumOfIdentityByStatus":
			node.GetNumOfIdentityByStatus(res, conn)
		}
		return
	} else if res["Type"] == "userlog" { // 用户日志类型操作
		switch res["Command"] {
		//case "GetAllLogByIdentity":
		//	node.GetAllLogByIdentty(res, conn)
		//case "GetAllLogByTimestamp":
		//	node.GetAllLogByTimestamp(res, conn)
		//case "GetPageLogByIdentity":
		//	node.GetPageLogByIdentity(res, conn)
		//case "GetPageLogByTimestamp":
		//	node.GetPageLogByTimestamp(res, conn)
		//case "GetPageLogByIdentityAndTimestamp":
		//	node.GetPageLogByIdentityAndTimestamp(res, conn)

		case "GetPageNormalLogsByIdentity":
			node.GetPageNormalLogsByIdentityforFE(res, conn)
		case "GetPageWarningLogsByIdentity":
			node.GetPageWarningLogsByIdentityforFE(res, conn)
		case "GetPageNormalLogsByIdentityAndTimestamp":
			node.GetPageNormalLogsByIdentityAndTimestampforFE(res, conn)
		case "GetPageWarningLogsByIdentityAndTimestamp":
			node.GetPageWarningLogsByIdentityAndTimestampforFE(res, conn)

		case "GetAllNormalLogsByTimestamp":
			node.GetAllNormalLogsByTimestampforFE(res, conn)
		case "GetAllWarningLogsByTimestamp":
			node.GetAllWarningLogsByTimestampforFE(res, conn)
		case "GetPageNormalLogsByTimestamp":
			node.GetPageNormalLogsByTimestampforFE(res, conn)
		case "GetPageWarningLogsByTimestamp":
			node.GetPageWarningLogsByTimestampforFE(res, conn)
		case "GetPageNormalLogsByUserNameAndTimestamp":
			node.GetPageNormalLogsByUserNameAndTimestampforFE(res, conn)
		case "GetPageWarningLogsByUserNameAndTimestamp":
			node.GetPageWarningLogsByUserNameAndTimestampforFE(res, conn)

		case "GetNumAndListByYearOfNormal":
			node.GetNumAndListByYearOfNormal(res, conn)
		case "GetNumAndListByYearOfWarning":
			node.GetNumAndListByYearOfWarning(res, conn)
		case "GetNumAndListByMonthOfNormal":
			node.GetNumAndListByMonthOfNormal(res, conn)
		case "GetNumAndListByMonthOfWarning":
			node.GetNumAndListByMonthOfWarning(res, conn)
		case "GetNumAndListByDayOfNormal":
			node.GetNumAndListByDayOfNormal(res, conn)
		case "GetNumAndListByDayOfWarning":
			node.GetNumAndListByDayOfWarning(res, conn)

		case "GetUGroupLogNumByUGroupID":
			node.GetUGroupLogNumByUGroupIDforMIS(res, conn)
		case "GetNormalLogsAnalysis":
			node.GetNormalLogsAnalysisforMIS(res, conn)
		case "GetWarningLogsAnalysis":
			node.GetWarningLogsAnalysisforMIS(res, conn)
		case "GetNormalLogsAnalysisByUGroupID":
			node.GetNormalLogsAnalysisByUGroupIDforMIS(res, conn)
		case "GetWarningLogsAnalysisByUGroupID":
			node.GetWarningLogsAnalysisByUGroupIDforMIS(res, conn)
		}
		return
	} else {
		common.Logger.Error("no such interface!")
		return
	}
}

// SetUpConnection 建立连接 ，进行加密通信
//
// @Description:
// @receiver node
// @param res
// @param conn
//
func (node *Node) SetUpConnection(res map[string]interface{}, conn net.Conn) {
	common.Logger.Info("开始建立前后端连接")
	if res["Data"] == nil {
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "数据为空", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, "")
		return
	} //数据为空 报错 发送400
	sourceData := res["Data"].(string)
	decodeContent, err := base64.StdEncoding.DecodeString(sourceData) //进行base64解码
	if err != nil {
		common.Logger.Errorf("decode failed, ", err)
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "", Data: nil}
		data, _ := json.Marshal(resp)
		Network.SendResponse(conn, data, "")
		return
	}

	//非对称加密解密
	key := keymanager.KeyManager{}
	key.Init()
	key.SetPriKey(node.network.SSLPrikey)
	key.SetPubkey(node.network.SSLPubkey)

	if key.IsOnCurve() == false {
		common.Logger.Error("Server creates failed..., because the private key and public key don't match.")
	}
	result, err := key.Decrypt(string(decodeContent))
	if result == nil || err != nil {
		common.Logger.Error(err)
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "", Data: nil}
		data, _ := json.Marshal(resp)
		Network.SendResponse(conn, data, "")
		return
	}

	common.Logger.Info("解析出来的密钥为", string(result))

	var request map[string]interface{}
	err = json.Unmarshal(result, &request)
	if err != nil {
		common.Logger.Error(err)
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "", Data: nil}
		data, _ := json.Marshal(resp)
		Network.SendResponse(conn, data, "")
		return
	}
	if request["SecretKey"] == nil {
		common.Logger.Error("解析出来的密钥为空")
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "", Data: nil}
		data, _ := json.Marshal(resp)
		Network.SendResponse(conn, data, "")
		return
	}

	secretKey := request["SecretKey"].(string)
	u1 := fmt.Sprintf("%16v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(1e16)) //生成uuid

	if _, ok := node.SessionCache.Get(u1); ok == true {
		common.Logger.Error("该SessionId已经存在 而且没有过期")
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "", Data: nil}
		data, _ := json.Marshal(resp)
		Network.SendResponse(conn, data, "")
		return
	}
	node.SessionCache.Set(u1, secretKey, cache.DefaultExpiration)
	//res["Key"].(string) = secretKey
	common.Logger.Info("对称密钥建立成功, SessionId:", u1, ", key", secretKey)
	msg, err := keymanager.SM4Encrypt(secretKey, []byte(u1))
	if err != nil {
		common.Logger.Error("SM4加密失败：", err)
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "", Data: nil}
		data, _ := json.Marshal(resp)
		Network.SendResponse(conn, data, "")
		return
	}

	encode := base64.RawURLEncoding.EncodeToString(msg)
	resp := CommonResponse{Code: code.SUCCESS, Message: encode}
	data, err := json.Marshal(resp)
	if err != nil {
		common.Logger.Error("json marshal failed: ", err)
		resp := CommonResponse{Code: code.BAD_REQUEST, Message: "", Data: nil}
		data, _ := json.Marshal(resp)
		Network.SendResponse(conn, data, "")
		return
	}

	Network.SendResponse(conn, data, "")
	return
}

// Login 身份登录
//
// @Description:
// @receiver node
// @param res
// @param conn
//
func (node *Node) Login(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Password"] == nil || res["Timestamp"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return

	}

	var response CommonResponse

	if node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		node.mongo.UpdateIdentityModifyRecords(res)
		Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		if Identity.IsValid == code.INVALID {
			resp := CommonResponse{Code: code.BAD_REQUEST, Message: "该身份已被禁用，登录失败", Data: nil}
			data, err := json.Marshal(resp)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return
		} else if Identity.IsValid == code.WITHOUT_CERT {
			resp := CommonResponse{Code: code.BAD_REQUEST, Message: "该身份证书已被撤销，登录失败", Data: nil}
			data, err := json.Marshal(resp)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return
		}
		if Identity.Passwd == res["Password"].(string) {
			st, _ := utils.ParseWithLocation("Asia/Shanghai", Identity.Timestamp)
			//st,_ := time.Parse("2006-01-02 15:04:05",user.Timestamp)
			duration := time.Since(st).Hours()
			common.Logger.Info("duration：", duration)
			if duration < 75*24 {
				if Identity.IsValid == code.PENDING_REVIEW {
					resp := CommonResponse{Code: code.PENDING_SUCCESS, Message: "SUCCESS", Data: Identity}
					data, err := json.Marshal(resp)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				} else if res["IdentityIdentifier"].(string) == "root" {
					resp := CommonResponse{Code: code.ROOT_SUCCESS, Message: "SUCCESS", Data: Identity}
					data, err := json.Marshal(resp)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				} else {
					resp := CommonResponse{Code: code.NORMAL_SUCCESS, Message: "SUCCESS", Data: Identity}
					data, err := json.Marshal(resp)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				}
			}
			if duration >= 75*24 && duration < 90*24 {
				s := int64((90*24 - duration) / 24)
				msg := "only " + strconv.FormatInt(s, 10) + " days left"
				if Identity.IsValid == code.PENDING_REVIEW {
					resp := CommonResponse{Code: code.PENDING_WARNING, Message: msg, Data: Identity}
					data, err := json.Marshal(resp)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				} else if res["IdentityIdentifier"].(string) == "root" {
					resp := CommonResponse{Code: code.ROOT_WARNING, Message: msg, Data: Identity}
					data, err := json.Marshal(resp)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				} else {
					resp := CommonResponse{Code: code.NORMAL_WARNING, Message: msg, Data: Identity}
					data, err := json.Marshal(resp)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				}

			}
			if duration >= 90*24 {
				s := int64((duration - 90*24) / 24)
				msg := strconv.FormatInt(s, 10) + " days past due"
				resp := CommonResponse{Code: code.EXPIRED, Message: msg, Data: Identity}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			}
		} else {
			if node.rule.AllowVisit(Identity.IdentityIdentifier) {
				timesleft := strconv.Itoa(node.rule.RemainingVisits(Identity.IdentityIdentifier)[0])
				msg := "passowrd wrong,only " + timesleft + " remaining attempts"
				resp := CommonResponse{Code: code.UNARTHORIZED, Message: msg, Data: nil}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				common.Logger.Warn(Identity, "密码输入错误1次,剩余:", node.rule.RemainingVisits(Identity.IdentityIdentifier))
				return
			} else {
				resp := CommonResponse{Code: code.MORE_THAN_FIVE_FAILURE, Message: "continuous password typing error", Data: nil}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				common.Logger.Warn(Identity, "密码输入错误次数过多,稍后再试")
				return
			}
		}
	} else {
		response = CommonResponse{Code: code.NOT_FOUND, Message: "NO SUCH USER", Data: nil}
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
		return
	}
	Network.SendResponse(conn, data, res["Key"].(string))
	return
}

// LoginWithWeChat 身份扫码登录
//
// @Description:
// @receiver node
// @param res
// @param conn
//
func (node *Node) LoginWithWeChat(res map[string]interface{}, conn net.Conn) {
	if res["Code"] == nil || res["Timestamp"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return

	}

	var response CommonResponse

	wxinfo, err := node.wechat.GetWxOpenIdFromOauth2(res["Code"].(string))
	if err != nil {
		response.Code = code.BAD_REQUEST
		response.Message = err.Error()
		response.Data = nil
		common.Logger.Error("get wxinfo fail")
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	if node.mongo.HasIdentityData("wxunionid", wxinfo.Unionid) {
		Identity := node.mongo.GetOneIdentityFromDatabase("wxunionid", wxinfo.Unionid)
		res["IdentityIdentifier"] = Identity.IdentityIdentifier
		node.mongo.UpdateIdentityModifyRecords(res)

		if Identity.IsValid == code.INVALID {
			resp := CommonResponse{Code: code.BAD_REQUEST, Message: "该身份已被禁用，登录失败", Data: nil}
			data, err := json.Marshal(resp)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return
		} else if Identity.IsValid == code.WITHOUT_CERT {
			resp := CommonResponse{Code: code.BAD_REQUEST, Message: "该身份证书已被撤销，登录失败", Data: nil}
			data, err := json.Marshal(resp)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return
		}

		st, _ := utils.ParseWithLocation("Asia/Shanghai", Identity.Timestamp)
		//st,_ := time.Parse("2006-01-02 15:04:05",user.Timestamp)
		duration := time.Since(st).Hours()
		common.Logger.Info("duration：", duration)
		if duration < 75*24 {
			if Identity.IsValid == code.PENDING_REVIEW {
				resp := CommonResponse{Code: code.PENDING_SUCCESS, Message: "SUCCESS", Data: Identity}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			} else if Identity.IdentityIdentifier == "root" {
				resp := CommonResponse{Code: code.ROOT_SUCCESS, Message: "SUCCESS", Data: Identity}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			} else {
				resp := CommonResponse{Code: code.NORMAL_SUCCESS, Message: "SUCCESS", Data: Identity}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			}
		}
		if duration >= 75*24 && duration < 90*24 {
			s := int64((90*24 - duration) / 24)
			msg := "only " + strconv.FormatInt(s, 10) + " days left"
			if Identity.IsValid == code.PENDING_REVIEW {
				resp := CommonResponse{Code: code.PENDING_WARNING, Message: msg, Data: Identity}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			} else if Identity.IdentityIdentifier == "root" {
				resp := CommonResponse{Code: code.ROOT_WARNING, Message: msg, Data: Identity}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			} else {
				resp := CommonResponse{Code: code.NORMAL_WARNING, Message: msg, Data: Identity}
				data, err := json.Marshal(resp)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			}

		}
		if duration >= 90*24 {
			s := int64((duration - 90*24) / 24)
			msg := strconv.FormatInt(s, 10) + " days past due"
			resp := CommonResponse{Code: code.EXPIRED, Message: msg, Data: Identity}
			data, err := json.Marshal(resp)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return
		}

	} else {
		common.Logger.Error("no such user")
		response = CommonResponse{Code: code.NOT_FOUND, Message: "NO SUCH USER", Data: nil}
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
		return
	}
	Network.SendResponse(conn, data, res["Key"].(string))
	return
}

// IdentityAuthentication TODO 定义一个专门解析前端请求的结构体
func (node *Node) IdentityAuthenticationforMIS(res map[string]interface{}, conn net.Conn) {
	var response CommonResponse
	if res["IdentityIdentifier"] == nil || res["Phone"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return

	} else {
		vc := node.sms.GenerateVerificationCode()
		node.sms.VerificationCode.Set(res["Phone"].(string), &vc, 10*time.Minute)
		err := node.sms.Sendmessage(res["Phone"].(string))
		if err != nil {
			common.Logger.Error("send vc err: ", err.Error())
			response.Code = code.BAD_REQUEST
			response.Message = err.Error()
			response.Data = nil
			data, err := json.Marshal(response)
			if err != nil {
				common.Logger.Error(err)
				return
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return
		}
	}
	response.Code = code.SUCCESS
	response.Message = "send vc!"
	response.Data = nil
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
		return
	}
	Network.SendResponse(conn, data, res["Key"].(string))
	return

}

// IdentityRegistry 身份注册
//
// @Description: 由普通管理员注册普通身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) IdentityRegistry(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Pubkey"] == nil || res["Passwd"] == nil || res["PrikeyEncrypted"] == nil || res["Phone"] == nil || res["VerificationCode"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	var response CommonResponse

	vc, ok := node.sms.VerificationCode.Get(res["Phone"].(string))
	if !ok {
		common.Logger.Error(res["Phone"].(string), "Verification code expired or does not exist, please resend")
		response.Code = code.UNARTHORIZED
		response.Message = "Verification code expired or does not exist, please resend"
		response.Data = nil
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
			return
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	vcs := vc.(*string)
	if res["VerificationCode"].(string) != *vcs {
		common.Logger.Error(res["Phone"].(string), "Verification code error")
		response.Code = code.UNARTHORIZED
		response.Message = "Verification code error"
		response.Data = nil
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
			return
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	if node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		common.Logger.Error("数据库已经存在该身份标识，注册失败", res["IdentityIdentifier"].(string))
		response.Code = code.BAD_REQUEST
		response.Message = "数据库已经存在该身份标识"
		response.Data = nil
	} else if node.mongo.HasIdentityData("pubkey", res["Pubkey"].(string)) {
		common.Logger.Error("用户公钥重复，注册失败")
		response.Code = code.BAD_REQUEST
		response.Message = "用户公钥重复，注册失败"
		response.Data = nil
	} else {
		var transaction MetaData.Identity
		transaction.Type = res["Type"].(string)
		transaction.Command = res["Command"].(string)
		transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)
		transaction.KeyParam = MetaData.KeyParam{0, 0}
		transaction.Pubkey = res["Pubkey"].(string)
		transaction.Passwd = res["Passwd"].(string)
		transaction.Timestamp = time.Now().Format("2006-01-02 15:04:05")
		transaction.IsValid = code.PENDING_REVIEW
		transaction.IPIdentifier = res["IPIdentifier"].(string)
		transaction.ModifyRecords = append(transaction.ModifyRecords, MetaData.ModifyRecord{Type: res["Type"].(string),
			Command: res["Command"].(string), Timestamp: time.Now().Format("2006-01-02 15:04:05")})
		transaction.Phone = res["Phone"].(string)
		transaction.PrikeyEncrypted = res["PrikeyEncrypted"].(string)

		//// 填充证书内容
		//pub := sm2.Sm2PublicKey{}
		//pub.SetBytes([]byte(transaction.Pubkey))
		//var pubkey security.PublicKey = &pub
		//cert := cert.Certificate{}
		//cert.Version = 0
		//cert.SerialNumber = 1
		//cert.PublicKey = pubkey
		//cert.SignatureAlgorithm = 0
		//cert.PublicKeyAlgorithm = 0
		//cert.IssueTo = transaction.IdentityIdentifier
		//cert.Issuer = "root"
		//cert.NotBefore = time.Now().Unix()
		//cert.NotAfter = time.Now().AddDate(1, 0, 0).Unix()
		//cert.KeyUsage = security.CertSign
		//cert.IsCA = false
		//cert.Timestamp = time.Now().Unix()
		//
		//pri := sm2.Sm2PrivateKey{}
		//pri.SetBytes([]byte(node.keyManager.GetPriKey()))
		//var prikey security.PrivateKey = &pri
		//err := cert.SignCert(prikey)
		//if err != nil {
		//	common.Logger.Error(err)
		//}
		//
		//c, err := cert.ToPem([]byte(transaction.Passwd), 0)
		//if err != nil {
		//	fmt.Println("证书签发失败：", err)
		//	response.Code = code.BAD_REQUEST
		//	response.Message = "身份证书签发失败"
		//	response.Data = nil
		//} else {
		//	var transactionHeader MetaData.TransactionHeader
		//	transactionHeader.TXType = MetaData.IdentityAction
		//	transaction.Cert = c
		//	response.Code = code.SUCCESS
		//	response.Message = "注册成功"
		//	response.Data = transaction
		//	node.txPool.PushbackTransaction(transactionHeader, &transaction)
		//	node.registryList[transaction.Pubkey] = node.mongo.Height
		//}
		transaction.Cert = ""
		var transactionHeader MetaData.TransactionHeader
		transactionHeader.TXType = MetaData.IdentityAction
		response.Code = code.SUCCESS
		response.Message = "申请注册成功，待管理员审核"
		response.Data = transaction
		node.txPool.PushbackTransaction(transactionHeader, &transaction)
		node.registryList[transaction.Pubkey] = node.mongo.Height
	}
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
		return
	}
	Network.SendResponse(conn, data, res["Key"].(string))
	return
}

// BindWeChat 微信绑定身份
//
// @Description: 微信绑定身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) BindWeChat(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Code"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	var response CommonResponse

	wxinfo, err := node.wechat.GetWxOpenIdFromOauth2(res["Code"].(string))
	if err != nil {
		response.Code = code.BAD_REQUEST
		response.Message = err.Error()
		response.Data = nil
		common.Logger.Error("get wxinfo fail")
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		common.Logger.Error("数据库不存在该身份标识，绑定失败", res["IdentityIdentifier"].(string))
		response.Code = code.BAD_REQUEST
		response.Message = "数据库不存在该身份标识"
		response.Data = nil
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		if node.mongo.HasIdentityData("wxunionid", wxinfo.Unionid) || identity.WXUnionID != "" {
			common.Logger.Error("该微信已经绑定过身份，绑定失败")
			response.Code = code.BAD_REQUEST
			response.Message = "该微信已经绑定过身份，绑定失败"
			response.Data = nil
		} else {
			var transaction MetaData.Identity
			transaction = identity
			transaction.Type = res["Type"].(string)
			transaction.Command = res["Command"].(string)
			transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)
			transaction.WXUnionID = wxinfo.Unionid

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			//i := transaction.ParseBCIdentityToCommon()
			//err := node.network.Keychain.SaveIdentity(&i, true)
			//if err != nil {
			//	common.Logger.Error(err)
			//}
			//common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

			response.Code = code.SUCCESS
			response.Message = "修改成功"
			response.Data = nil
			node.mongo.UpdateIdentityModifyRecords(res)
		}
	}
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
		return
	}

	Network.SendResponse(conn, data, res["Key"].(string))
	return
}

// UnBindWeChat 身份解绑微信
//
// @Description: 身份解绑微信
// @receiver node
// @param res
// @param conn
//
func (node *Node) UnBindWeChat(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	var response CommonResponse

	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		common.Logger.Error("数据库不存在该身份标识，解绑失败", res["IdentityIdentifier"].(string))
		response.Code = code.BAD_REQUEST
		response.Message = "数据库不存在该身份标识"
		response.Data = nil
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		if identity.WXUnionID == "" {
			common.Logger.Error("该微信尚未绑定过身份，解绑失败")
			response.Code = code.BAD_REQUEST
			response.Message = "该微信尚未绑定过身份，解绑失败"
			response.Data = nil
		} else {
			var transaction MetaData.Identity
			transaction = identity
			transaction.Type = res["Type"].(string)
			transaction.Command = res["Command"].(string)
			transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)
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

			response.Code = code.SUCCESS
			response.Message = "修改成功"
			response.Data = nil
			node.mongo.UpdateIdentityModifyRecords(res)
		}
	}
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
		return
	}

	Network.SendResponse(conn, data, res["Key"].(string))
	return
}

// ResetValidation 身份有效性修改
//
// @Description: 由超级管理员来修改其他身份的有效性
// @receiver node
// @param res
// @param conn
//
func (node *Node) ResetValidation(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["IsValid"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	isvalid := int(res["IsValid"].(float64))
	node.mongo.UpdateIdentityModifyRecords(res)
	var response CommonResponse

	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		response.Code = code.NOT_FOUND
		response.Message = "数据库不存在该身份"
		response.Data = nil
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		// 审核身份，颁发证书
		if identity.IsValid == code.PENDING_REVIEW {
			if isvalid == code.VALID {
				var transaction MetaData.Identity
				transaction.Type = res["Type"].(string)
				transaction.Command = "EnableIdentity"
				transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)

				// 填充证书内容
				pub := sm2.Sm2PublicKey{}
				pub.SetBytes([]byte(identity.Pubkey))
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
					common.Logger.Error("证书签名失败：", err)
					response.Code = code.BAD_REQUEST
					response.Message = "身份证书签名失败"
					response.Data = nil

					data, err := json.Marshal(response)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				}

				c, err := cert.ToPem([]byte(identity.Passwd), 0)
				if err != nil {
					common.Logger.Error("证书签发失败：", err)
					response.Code = code.BAD_REQUEST
					response.Message = "身份证书签发失败"
					response.Data = nil

					data, err := json.Marshal(response)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				} else {
					var transactionHeader MetaData.TransactionHeader
					transactionHeader.TXType = MetaData.IdentityAction
					transaction.Cert = c
					transaction.IsValid = code.VALID
					transaction.KeyParam = identity.KeyParam
					transaction.Pubkey = identity.Pubkey
					transaction.Passwd = identity.Passwd
					transaction.Timestamp = identity.Timestamp
					transaction.Phone = identity.Phone
					transaction.PrikeyEncrypted = identity.PrikeyEncrypted

					transaction.IPIdentifier = identity.IPIdentifier
					transaction.ModifyRecords = identity.ModifyRecords

					response.Code = code.SUCCESS
					response.Message = "通过注册请求"
					response.Data = transaction

					node.txPool.PushbackTransaction(transactionHeader, &transaction)
					node.registryList[transaction.Pubkey] = node.mongo.Height

					i := transaction.ParseBCIdentityToCommon()
					err := node.network.Keychain.SaveIdentity(&i, true)
					if err != nil {
						common.Logger.Error(err)
					}
					common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())
					data, err := json.Marshal(response)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				}
			} else if isvalid == code.INVALID {
				var transaction MetaData.Identity
				transaction.Type = res["Type"].(string)
				transaction.Command = "DestroyByIdentityIdentifier"
				transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)

				var transactionHeader MetaData.TransactionHeader
				transactionHeader.TXType = MetaData.IdentityAction
				node.txPool.PushbackTransaction(transactionHeader, &transaction)

				response.Code = code.SUCCESS
				response.Message = "已拒绝该身份的注册申请"
				response.Data = nil

				data, err := json.Marshal(response)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			}
		} else if identity.IsValid == code.WITHOUT_CERT {
			if isvalid == code.VALID {
				var transaction MetaData.Identity
				transaction.Type = res["Type"].(string)
				transaction.Command = "CertReissue"
				transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)

				// 填充证书内容
				pub := sm2.Sm2PublicKey{}
				pub.SetBytes([]byte(identity.Pubkey))
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
					common.Logger.Error("证书签名失败：", err)
					response.Code = code.BAD_REQUEST
					response.Message = "身份证书签发失败"
					response.Data = nil

					data, err := json.Marshal(response)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				}

				c, err := cert.ToPem([]byte(identity.Passwd), 0)
				if err != nil {
					common.Logger.Error("证书签发失败：", err)
					response.Code = code.BAD_REQUEST
					response.Message = "身份证书签发失败"
					response.Data = nil

					data, err := json.Marshal(response)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				} else {
					var transactionHeader MetaData.TransactionHeader
					transactionHeader.TXType = MetaData.IdentityAction
					transaction.Cert = c
					transaction.IsValid = code.VALID
					transaction.KeyParam = identity.KeyParam
					transaction.Pubkey = identity.Pubkey
					transaction.Passwd = identity.Passwd
					transaction.Timestamp = identity.Timestamp
					transaction.Phone = identity.Phone
					transaction.PrikeyEncrypted = identity.PrikeyEncrypted

					transaction.IPIdentifier = identity.IPIdentifier
					transaction.ModifyRecords = identity.ModifyRecords

					response.Code = code.SUCCESS
					response.Message = "通过重新申请证书的请求"
					response.Data = transaction

					node.txPool.PushbackTransaction(transactionHeader, &transaction)
					node.registryList[transaction.Pubkey] = node.mongo.Height

					i := transaction.ParseBCIdentityToCommon()
					err := node.network.Keychain.SaveIdentity(&i, true)
					if err != nil {
						common.Logger.Error(err)
					}
					common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

					data, err := json.Marshal(response)
					if err != nil {
						common.Logger.Error(err)
					}
					Network.SendResponse(conn, data, res["Key"].(string))
					return
				}
			}
		} else if identity.IsValid == code.VALID && isvalid == code.INVALID {
			var transaction MetaData.Identity
			transaction.Type = res["Type"].(string)
			transaction.Command = "ResetValidation"
			transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)

			transaction.IsValid = code.INVALID

			response.Code = code.SUCCESS
			response.Message = "身份禁用成功"
			response.Data = false

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			data, err := json.Marshal(response)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return

		} else if identity.IsValid == code.INVALID && isvalid == code.VALID {
			var transaction MetaData.Identity
			transaction = identity
			transaction.Type = res["Type"].(string)
			transaction.Command = "ResetValidation"
			transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)

			transaction.IsValid = code.VALID

			response.Code = code.SUCCESS
			response.Message = "身份重新启用成功"
			response.Data = true

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			i := transaction.ParseBCIdentityToCommon()
			err := node.network.Keychain.SaveIdentity(&i, true)
			if err != nil {
				common.Logger.Error(err)
			}
			common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

			data, err := json.Marshal(response)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return

		} else if identity.IsValid == code.INVALID && isvalid == code.WITHOUT_CERT {
			var transaction MetaData.Identity
			transaction.Type = res["Type"].(string)
			transaction.Command = "CertRevocation"
			transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)

			transaction.IsValid = code.WITHOUT_CERT

			response.Code = code.SUCCESS
			response.Message = "身份证书撤销申请成功"
			response.Data = true

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			i := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
			flag, err := node.network.Keychain.DeleteIdentityByName(transaction.IdentityIdentifier, i.Passwd)
			if err != nil {
				common.Logger.Error(err)
			} else if flag == true {
				common.Logger.Info("sqlite删除身份成功")
			} else {
				common.Logger.Info("sqlite删除身份失败")
			}
			if node.config.IsMINConn {
				node.SendCertRevocationMessageToMIR(res["IdentityIdentifier"].(string))
			}
			common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities(), "默认身份：", node.network.Keychain.GetCurrentIdentity())

			data, err := json.Marshal(response)
			if err != nil {
				common.Logger.Error(err)
			}
			Network.SendResponse(conn, data, res["Key"].(string))
			return
		} else {
			response.Code = code.SERVICE_UNAVAILABLE
			response.Message = "操作不合规"
			response.Data = false
		}

		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
	}
}

// GetAllPendingIdentity 获取所有待审核的身份
//
// @Description: 获取所有待审核的身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllPendingIdentity(res map[string]interface{}, conn net.Conn) {
	identities := node.mongo.GetPendingIdentityFromDatabase()
	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取所有待审核身份成功"
	response.Data = identities
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllPendingIdentityByPage 按页获取所有待审核的身份
//
// @Description: 按页获取所有待审核的身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllPendingIdentityByPage(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPagePendingIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetPendingIdentityCountFromDatabase()

	var response CommonResponse
	response.Code = 200
	response.Message = "获取分页待审核身份信息成功"
	response.Data = message
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllCheckedIdentity 获取所有已审核的身份
//
// @Description: 获取所有已审核的身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllCheckedIdentity(res map[string]interface{}, conn net.Conn) {
	identities := node.mongo.GetCheckedIdentityCountFromDatabase()
	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取所有已审核身份成功"
	response.Data = identities
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllPendingIdentityByPage 按页获取所有待审核的身份
//
// @Description: 按页获取所有待审核的身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllCheckedIdentityByPage(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageCheckedIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetCheckedIdentityCountFromDatabase()

	var response CommonResponse
	response.Code = 200
	response.Message = "获取分页已审核身份信息成功"
	response.Data = message
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllDisabledIdentityByPage 按页获取所有禁用的身份
//
// @Description: 按页获取所有禁用的身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllDisabledIdentityByPage(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageDisabledIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetDisabledIdentityCountFromDatabase()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取分页禁用身份信息成功"
	response.Data = message
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllAbledIdentity 按页获取所有正常的身份
//
// @Description: 按页获取所有正常的身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllAbledIdentityByPage(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageAbledIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetAbledIdentityCountFromDatabase()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取分页正常身份信息成功"
	response.Data = message
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllWithoutCertIdentityByPage 按页获取所有没有证书的身份
//
// @Description: 按页获取所有没有证书的身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllWithoutCertIdentityByPage(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageWithoutCertIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetWithoutCertIdentityCountFromDatabase()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取分页证书撤销身份信息成功"
	response.Data = message
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllActionsByIdentityIdentifier 获得某个用户的历史行为信息
//
// @Description: 获得某个用户的历史行为信息
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllActionsByIdentityIdentifier(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	var response CommonResponse
	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		response.Code = code.NOT_FOUND
		response.Message = "不存在该身份"
		response.Data = MetaData.Identity{}
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))

		response.Code = code.SUCCESS
		response.Message = "成功获得该身份行为信息"
		response.Data = identity.ModifyRecords
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

type IdentityActionsResponse struct {
	Records []MetaData.ModifyRecord
	Total   int
}

// GetAllActionsByIdentityIdentifierAndPage 获得某个用户的分页历史行为信息
//
// @Description: 获得某个用户的分页历史行为信息
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllActionsByIdentityIdentifierAndPage(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	var response CommonResponse
	var data IdentityActionsResponse
	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		response.Code = code.NOT_FOUND
		response.Message = "不存在该身份"
		response.Data = MetaData.Identity{}
	} else {
		pageSize := int(res["PageSize"].(float64))
		pageNum := int(res["PageNum"].(float64))
		skip := pageSize * (pageNum - 1)

		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		l := len(identity.ModifyRecords)
		data.Total = l
		if skip >= l {
			response.Code = code.BAD_REQUEST
			response.Message = "超出长度范围"
			response.Data = nil
		} else if l-skip < pageSize {
			response.Code = code.SUCCESS
			response.Message = "成功获得该身份行为信息"
			data.Records = identity.ModifyRecords[skip:]
			response.Data = data
		} else {
			response.Code = code.SUCCESS
			response.Message = "成功获得该身份行为信息"
			data.Records = identity.ModifyRecords[skip : skip+pageSize]
			response.Data = data
		}
	}

	d, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, d, res["Key"].(string))
}

type NumOfIdentity struct {
	Pending     int
	WithoutCert int
	Valid       int
	InValid     int
}

// GetNumOfIdentityByStatus 获取禁用、正常、待审核、撤销证书身份数量
//
// @Description: 获取禁用、正常、待审核、撤销证书身份数量
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetNumOfIdentityByStatus(res map[string]interface{}, conn net.Conn) {
	var m NumOfIdentity
	m.Valid = node.mongo.GetAbledIdentityCountFromDatabase()
	m.InValid = node.mongo.GetDisabledIdentityCountFromDatabase()
	m.Pending = node.mongo.GetPendingIdentityCountFromDatabase()
	m.WithoutCert = node.mongo.GetWithoutCertIdentityCountFromDatabase()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取禁用、正常、待审核、撤销证书身份数量"
	response.Data = m
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// IdentityDestroyByIdentityIdentifier 身份注销
//
// @Description: 超级管理员的身份注销权限
// @receiver node
// @param res
// @param conn
//
func (node *Node) IdentityDestroyByIdentityIdentifier(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	var response CommonResponse
	node.mongo.UpdateIdentityModifyRecords(res)

	if node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		// identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))

		if node.config.MyAddress.Port == 5010 {
			err := node.SendRemoveUserToVMS(res["IdentityIdentifier"].(string))
			if err != nil && err.Error() != "user not exist" {
				response.Code = code.BAD_REQUEST
				response.Message = err.Error()
				response.Data = nil

				data, err := json.Marshal(response)
				if err != nil {
					common.Logger.Error(err)
				}
				Network.SendResponse(conn, data, res["Key"].(string))
				return
			}
		}

		var transaction MetaData.Identity
		transaction.Type = res["Type"].(string)
		transaction.Command = res["Command"].(string)
		transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)

		var transactionHeader MetaData.TransactionHeader
		transactionHeader.TXType = MetaData.IdentityAction
		node.txPool.PushbackTransaction(transactionHeader, &transaction)

		//i := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		//flag, err := node.network.Keychain.DeleteIdentityByName(transaction.IdentityIdentifier, i.Passwd)
		//if err != nil {
		//	common.Logger.Error(err)
		//} else if flag == true {
		//	common.Logger.Info("sqlite删除身份成功")
		//} else {
		//	common.Logger.Info("sqlite删除身份失败")
		//}

		response.Code = code.SUCCESS
		response.Message = "注销成功"
		response.Data = nil

		if node.config.IsMINConn {
			node.SendCertRevocationMessageToMIR(res["IdentityIdentifier"].(string))
		}

	} else {
		response.Code = code.NOT_FOUND
		response.Message = "数据库不存在该用户"
		response.Data = nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	//common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())
	Network.SendResponse(conn, data, res["Key"].(string))
	//node.SendCertRevocationMessageToMIR(res["IdentityIdentifier"].(string))
}

// GetValidIdentity 新设备上获取已注册的身份信息
//
// @Description: 提供给MIS前端的身份获取接口
// @receiver node
// @param res
// @param resp
// @return *network.NetResponse
//
func (node *Node) GetValidIdentityforMIS(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Passwd"] == nil || res["Phone"] == nil || res["VerificationCode"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	var response CommonResponse

	vc, ok := node.sms.VerificationCode.Get(res["Phone"].(string))
	if !ok {
		common.Logger.Error(res["Phone"].(string), "Verification code expired or does not exist, please resend")
		response.Code = code.UNARTHORIZED
		response.Message = "Verification code expired or does not exist, please resend"
		response.Data = nil
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
			return
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	vcs := vc.(*string)
	if res["VerificationCode"].(string) != *vcs {
		common.Logger.Error(res["Phone"].(string), "Verification code error")
		response.Code = code.UNARTHORIZED
		response.Message = "Verification code error"
		response.Data = nil
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
			return
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		common.Logger.Error("The identity does not exist, and the acquisition fails", res["IdentityIdentifier"].(string))
		response.Code = code.NOT_FOUND
		response.Message = "The identity does not exist, and the acquisition fails"
		response.Data = nil
	} else {
		Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		// common.Logger.Info("Identity is:",Identity)
		if Identity.IsValid == code.INVALID {
			response.Code = code.BAD_REQUEST
			response.Message = "The identity has been disabled and the acquisition failed"
			response.Data = nil
		} else if Identity.IsValid == code.WITHOUT_CERT {
			response.Code = code.BAD_REQUEST
			response.Message = "The identity certificate has been revoked and failed to obtain"
			response.Data = nil
		} else if res["Passwd"].(string) != Identity.Passwd {
			response.Code = code.BAD_REQUEST
			response.Message = "Wrong password"
			response.Data = nil
		} else if Identity.Phone != "" && res["Phone"] != Identity.Phone {
			response.Code = code.BAD_REQUEST
			response.Message = "The identity and mobile phone number do not match, verification failed"
			response.Data = nil
		} else if Identity.PrikeyEncrypted == "" {
			response.Code = code.BAD_REQUEST
			response.Message = "Please upload the private key information from the device with the private key"
			response.Data = nil
		} else {
			response.Code = code.SUCCESS
			var gr GetIdentityRespond
			gr.IdentityIdentifier = Identity.IdentityIdentifier
			gr.Phone = Identity.Phone
			gr.PrikeyEncrypted = Identity.PrikeyEncrypted
			gr.Pubkey = Identity.Pubkey
			gr.Cert = Identity.Cert
			//data, err := json.Marshal(gr)
			//if err != nil {
			//	common.Logger.Error("Identity resolution failed: ", err)
			//	response.Code = code.BAD_REQUEST
			//	response.Message = "Identity resolution failed"
			//}
			response.Data = gr
			data, err := json.Marshal(response)
			if err != nil {
				common.Logger.Error(err)
				return
			}
			Network.SendResponse(conn, data, res["Key"].(string))
		}
	}
}

// IdentityResetPassword 身份密码的修改
//
// @Description: 由普通管理员注册普通身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) IdentityResetPassword(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Passwd"] == nil || res["Previous"] == nil || res["PrikeyEncrypted"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	node.mongo.UpdateIdentityModifyRecords(res)
	var response CommonResponse
	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		response.Code = code.NOT_FOUND
		response.Message = "数据库不存在该身份"
		response.Data = nil
	} else if identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string)); identity.Passwd != res["Previous"].(string) {
		response.Code = code.UNAUTHORIZED
		response.Message = "原密码错误"
		response.Data = nil
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		var transaction MetaData.Identity
		transaction = identity
		transaction.Type = res["Type"].(string)
		transaction.Command = res["Command"].(string)
		transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)
		transaction.Passwd = res["Passwd"].(string)
		transaction.PrikeyEncrypted = res["PrikeyEncrypted"].(string)

		var transactionHeader MetaData.TransactionHeader
		transactionHeader.TXType = MetaData.IdentityAction
		node.txPool.PushbackTransaction(transactionHeader, &transaction)

		i := transaction.ParseBCIdentityToCommon()
		err := node.network.Keychain.SaveIdentity(&i, true)
		if err != nil {
			common.Logger.Error(err)
		}
		common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

		response.Code = code.SUCCESS
		response.Message = "修改成功"
		response.Data = nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// IdentityCheckPassword 身份密码的检验
//
// @Description:
// @receiver node
// @param res
// @param conn
//
func (node *Node) IdentityCheckPassword(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Passwd"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	var response CommonResponse
	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		response.Code = code.NOT_FOUND
		response.Message = "数据库不存在该身份"
		response.Data = nil
	} else if identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string)); identity.Passwd != res["Passwd"].(string) {
		response.Code = code.UNAUTHORIZED
		response.Message = "密码错误"
		response.Data = nil
	} else {
		response.Code = code.SUCCESS
		response.Message = "密码正确"
		response.Data = nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) UploadEncryptedPrikeyforMIS(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Passwd"] == nil || res["Phone"] == nil || res["VerificationCode"] == nil || res["PrikeyEncrypted"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	var response CommonResponse

	vc, ok := node.sms.VerificationCode.Get(res["Phone"].(string))
	if !ok {
		common.Logger.Error(res["Phone"].(string), "Verification code expired or does not exist, please resend")
		response.Code = code.UNARTHORIZED
		response.Message = "Verification code expired or does not exist, please resend"
		response.Data = nil
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
			return
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	vcs := vc.(*string)
	if res["VerificationCode"].(string) != *vcs {
		common.Logger.Error(res["Phone"].(string), "Verification code error")
		response.Code = code.UNARTHORIZED
		response.Message = "Verification code error"
		response.Data = nil
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error(err)
			return
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		common.Logger.Error("The identity does not exist, and the acquisition fails", res["IdentityIdentifier"].(string))
		response.Code = code.NOT_FOUND
		response.Message = "The identity does not exist, and the acquisition fails"
		response.Data = nil
	} else {
		Identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		if res["Passwd"].(string) != Identity.Passwd {
			response.Code = code.BAD_REQUEST
			response.Message = "Wrong password"
			response.Data = nil
		} else if Identity.Phone != "" || Identity.PrikeyEncrypted != "" {
			response.Code = code.BAD_REQUEST
			response.Message = "The identity has uploaded a private key"
			response.Data = nil
		} else {
			var transaction MetaData.Identity
			transaction = Identity
			transaction.Type = "identity-act"
			transaction.Command = "UploadEncryptedPrikey"
			transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)
			transaction.PrikeyEncrypted = res["PrikeyEncrypted"].(string)
			transaction.Phone = res["Phone"].(string)

			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.IdentityAction
			node.txPool.PushbackTransaction(transactionHeader, &transaction)

			i := transaction.ParseBCIdentityToCommon()
			err := node.network.Keychain.SaveIdentity(&i, true)
			if err != nil {
				common.Logger.Error(err)
			}
			// common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

			response.Code = code.SUCCESS
			response.Data = nil

		}
	}
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// IdentityResetIPIdentifier 身份IP的修改
//
// @Description:
// @receiver node
// @param res
// @param conn
//
func (node *Node) IdentityResetIPIdentifier(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["IPIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	node.mongo.UpdateIdentityModifyRecords(res)
	var response CommonResponse
	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		response.Code = code.NOT_FOUND
		response.Message = "数据库不存在该身份"
		response.Data = nil
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
		var transaction MetaData.Identity
		transaction = identity
		transaction.Type = res["Type"].(string)
		transaction.Command = res["Command"].(string)
		transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)
		transaction.IPIdentifier = res["IPIdentifier"].(string)

		var transactionHeader MetaData.TransactionHeader
		transactionHeader.TXType = MetaData.IdentityAction
		node.txPool.PushbackTransaction(transactionHeader, &transaction)

		i := transaction.ParseBCIdentityToCommon()
		err := node.network.Keychain.SaveIdentity(&i, true)
		if err != nil {
			common.Logger.Error(err)
		}
		common.Logger.Info("当前身份：", node.network.Keychain.GetAllIdentities())

		response.Code = code.SUCCESS
		response.Message = "修改成功"
		response.Data = nil
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllIdentityAllInf 获取所有身份的所有信息
//
// @Description: 获取所有身份的所有信息
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllIdentityAllInf(res map[string]interface{}, conn net.Conn) { //
	identities := node.mongo.GetAllIdentityFromDatabase()
	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取所有身份信息成功"
	response.Data = identities
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllIdentityAllInfByPage 按页获取身份的所有信息
//
// @Description: 按页获取身份的所有信息
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllIdentityAllInfByPage(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetIdentityCountFromDatabase()

	var response CommonResponse
	response.Code = 200
	response.Message = "获取分页身份信息成功"
	response.Data = message
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

//func (node *Blockchain) GetAllIdentityImmutableInf(res map[string]interface{}, conn net.Conn) { //
//	var info []IdentityImmutableInf
//	resquest := node.mongo.GetAllIdentityFromDatabase()
//	for _, x := range resquest {
//		var IdentityImmutable IdentityImmutableInf
//		IdentityImmutable.IdentityIdentifier = x.IdentityIdentifier
//		IdentityImmutable.Pubkey = x.Pubkey
//		IdentityImmutable.Cert = x.Cert
//		IdentityImmutable.Timestamp = x.Timestamp
//		IdentityImmutable.KeyParam = x.KeyParam
//
//		info = append(info, IdentityImmutable)
//	}
//	var response GetIdentityImmutableInfResponse
//	response.StatusCode = 200
//	response.MessageType = "json"
//	response.Message = info
//	fmt.Println("the info is ", info)
//	data, err := json.Marshal(response)
//	if err != nil {
//		fmt.Println(err)
//	}
//	Network.SendResponse(conn, data, res["SecretKey"].(string))
//}
//
//func (node *Blockchain) GetAllIdentityAllImmutableInfByPage(res map[string]interface{}, conn net.Conn) {
//	if res["PageSize"] == nil || res["PageNum"] == nil {
//		return
//	}
//	pageSize := int(res["PageSize"].(float64))
//	pageNUm := int(res["PageNum"].(float64))
//	skip := pageSize * (pageNUm - 1)
//
//	var info []IdentityImmutableInf
//	resp := node.mongo.GetPageIdentityFromDatabase(skip, pageSize)
//	for _, x := range resp {
//		var IdentityImmutable IdentityImmutableInf
//		IdentityImmutable.IdentityIdentifier = x.IdentityIdentifier
//		IdentityImmutable.Pubkey = x.Pubkey
//		IdentityImmutable.Cert = x.Cert
//		IdentityImmutable.Timestamp = x.Timestamp
//		IdentityImmutable.KeyParam = x.KeyParam
//		info = append(info, IdentityImmutable)
//	}
//	var message PageIdentityInf
//	message.Identities = info
//	message.Total = node.mongo.GetIdentityCountFromDatabase()
//
//	var response GetPageIdentityInfResponse
//	response.StatusCode = 200
//	response.MessageType = "json"
//	response.Message = message
//	data, err := json.Marshal(response)
//	if err != nil {
//		fmt.Println(err)
//	}
//	Network.SendResponse(conn, data, res["Key"].(string))
//}

// GetOneIdentityInfByIdentityIdentifier 通过身份标识来获取一个身份
//
// @Description: 通过身份标识来获取一个身份
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetOneIdentityInfByIdentityIdentifier(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	var response CommonResponse
	if !node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
		response.Code = code.NOT_FOUND
		response.Message = "不存在该身份"
		response.Data = MetaData.Identity{}
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))

		response.Code = code.SUCCESS
		response.Message = "成功获得该身份"
		response.Data = identity
	}

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetOneIdentityPublicKey 获取一个身份的公钥
//
// @Description: 获取一个身份的公钥
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetOneIdentityPublicKey(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "成功获取身份公钥"
	response.Data = identity.Pubkey
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllLogByIdentity 获取一个身份的所有用户日志
//
// @Description: 获取一个身份的所有用户日志
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllLogByIdentity(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	logs := node.mongo.GetLogsByIdentityIdentifierFromDatabase(res["IdentityIdentifier"].(string))
	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取该身份的所有日志成功"
	response.Data = logs
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetAllLogByTimestamp 按时间戳获取所有用户日志
//
// @Description: 获取一个身份的所有用户日志
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetAllLogByTimestamp(res map[string]interface{}, conn net.Conn) {
	if res["Start"] == nil || res["End"] == nil {
		return
	}
	start := res["Start"].(string)
	end := res["End"].(string)
	logs := node.mongo.GetLogsByRangeTimeFromDatabase(start, end)

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按时段获取所有日志成功"
	response.Data = logs
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetPageLogByIdentity 按身份获取分页日志
//
// @Description: 按身份获取分页日志
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetPageLogByIdentity(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["PageSize"] == nil || res["PageNum"] == nil {
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)
	logs := node.mongo.GetPageLogsByIdentityIdentifierFromDatabase(res["IdentityIdentifier"].(string), skip, pageSize)
	total := node.mongo.GetPageLogsCountByIdentityIdentifierFromDatabase(res["IdentityIdentifier"].(string))
	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = strconv.Itoa(total)
	response.Data = logs
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageLogByTimestamp(res map[string]interface{}, conn net.Conn) {
	if res["Start"] == nil || res["End"] == nil || res["PageSize"] == nil || res["PageNum"] == nil {
		return
	}
	start := res["Start"].(string)
	end := res["End"].(string)
	pageSize := int(res["PageSize"].(float64))
	pageNUm := int(res["PageNum"].(float64))
	skip := pageSize * (pageNUm - 1)

	logs := node.mongo.GetPageLogsByRangeTimeFromDatabase(start, end, skip, pageSize)
	total := node.mongo.GetPageLogsCountByRangeTimeFromDatabase(start, end)

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = strconv.Itoa(total)
	response.Data = logs

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageLogByIdentityAndTimestamp(res map[string]interface{}, conn net.Conn) {
	if res["IdentityIdentifier"] == nil || res["Start"] == nil || res["End"] == nil || res["PageSize"] == nil || res["PageNum"] == nil {
		return
	}
	start := res["Start"].(string)
	end := res["End"].(string)
	pageSize := int(res["PageSize"].(float64))
	pageNUm := int(res["PageNum"].(float64))
	skip := pageSize * (pageNUm - 1)

	logs := node.mongo.GetPageLogsByIdentityAndRangeTimeFromDatabase(res["IdentityIdentifier"].(string), start, end, skip, pageSize)
	total := node.mongo.GetPageLogsCountByIdentityAndRangeTimeFromDatabase(res["IdentityIdentifier"].(string), start, end)

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = strconv.Itoa(total)
	response.Data = logs

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetAllNormalLogsByTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	logs := node.mongo.GetNormalLogsByTimestampFromDatabase(start, end)
	total := node.mongo.GetNormalLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "分页获取所有正常日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageNormalLogsByTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["PageSize"] == nil || res["PageNo"] == nil || res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	if res["IdentityIdentifier"].(string) == "" {
		pageSize := int(res["PageSize"].(float64))
		pageNum := int(res["PageNo"].(float64))
		skip := pageSize * (pageNum - 1)
		start := res["BeginTime"].(string)
		end := res["EndTime"].(string)

		logs := node.mongo.GetPageNormalLogsByTimestampFromDatabase(start, end, skip, pageSize)
		total := node.mongo.GetPageNormalLogsCountByTimestampFromDatabase(start, end)

		logdata := PageUserlogRespond{Logs: logs, Count: total}

		var response CommonResponse
		response.Code = code.SUCCESS
		response.Message = "按时间分页获取所有正常日志成功"
		response.Data = logdata
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error("回复数据解析失败")
			response.Code = code.BAD_REQUEST
			response.Message = "回复数据解析失败"
			response.Data = nil
		}

		Network.SendResponse(conn, data, res["Key"].(string))
	} else if res["IdentityIdentifier"].(string) != "" {
		pageSize := int(res["PageSize"].(float64))
		pageNum := int(res["PageNo"].(float64))
		skip := pageSize * (pageNum - 1)
		start := res["BeginTime"].(string)
		end := res["EndTime"].(string)

		logs := node.mongo.GetPageNormalLogsByTimestampAndIdentifierFromDatabase(start, end, res["IdentityIdentifier"].(string), skip, pageSize)
		total := node.mongo.GetPageNormalLogsCountByTimestampAndIdentifierFromDatabase(start, end, res["IdentityIdentifier"].(string))

		logdata := PageUserlogRespond{Logs: logs, Count: total}

		var response CommonResponse
		response.Code = code.SUCCESS
		response.Message = "按时间分页获取所有正常日志成功"
		response.Data = logdata
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error("回复数据解析失败")
			response.Code = code.BAD_REQUEST
			response.Message = "回复数据解析失败"
			response.Data = nil
		}

		Network.SendResponse(conn, data, res["Key"].(string))
	}
}

func (node *Node) GetAllWarningLogsByTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	logs := node.mongo.GetAllWarningLogsByTimestampFromDatabase(start, end)
	total := node.mongo.GetAllWarningLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按时间获取所有告警日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageWarningLogsByTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["PageSize"] == nil || res["PageNo"] == nil || res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	if res["IdentityIdentifier"].(string) == "" {
		pageSize := int(res["PageSize"].(float64))
		pageNum := int(res["PageNo"].(float64))
		skip := pageSize * (pageNum - 1)
		start := res["BeginTime"].(string)
		end := res["EndTime"].(string)

		logs := node.mongo.GetPageWarningLogsByTimestampFromDatabase(start, end, skip, pageSize)
		total := node.mongo.GetPageWarningLogsCountByTimestampFromDatabase(start, end)

		logdata := PageUserlogRespond{Logs: logs, Count: total}

		var response CommonResponse
		response.Code = code.SUCCESS
		response.Message = "按时间分页获取所有告警日志成功"
		response.Data = logdata
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error("回复数据解析失败")
			response.Code = code.BAD_REQUEST
			response.Message = "回复数据解析失败"
			response.Data = nil
		}

		Network.SendResponse(conn, data, res["Key"].(string))
	} else if res["IdentityIdentifier"].(string) != "" {
		pageSize := int(res["PageSize"].(float64))
		pageNum := int(res["PageNo"].(float64))
		skip := pageSize * (pageNum - 1)
		start := res["BeginTime"].(string)
		end := res["EndTime"].(string)

		logs := node.mongo.GetPageWarningLogsByTimestampAndIdentifierFromDatabase(start, end, res["IdentityIdentifier"].(string), skip, pageSize)
		total := node.mongo.GetPageWarningLogsCountByTimestampAndIdentifierFromDatabase(start, end, res["IdentityIdentifier"].(string))

		logdata := PageUserlogRespond{Logs: logs, Count: total}

		var response CommonResponse
		response.Code = code.SUCCESS
		response.Message = "按时间分页获取所有告警日志成功"
		response.Data = logdata
		data, err := json.Marshal(response)
		if err != nil {
			common.Logger.Error("回复数据解析失败")
			response.Code = code.BAD_REQUEST
			response.Message = "回复数据解析失败"
			response.Data = nil
		}

		Network.SendResponse(conn, data, res["Key"].(string))
	}
}

func (node *Node) GetPageNormalLogsByUserNameAndTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["PageSize"] == nil || res["PageNo"] == nil || res["UserName"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNo"].(float64))
	skip := pageSize * (pageNum - 1)
	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	logs := node.mongo.GetPageNormalLogsByUserNameAndTimestampFromDatabase(res["UserName"].(string), start, end, skip, pageSize)
	total := node.mongo.GetPageNormalLogsCountByUserNameAndTimestampFromDatabase(res["UserName"].(string), start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按时间和用户名分页获取正常日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageWarningLogsByUserNameAndTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["PageSize"] == nil || res["PageNo"] == nil || res["UserName"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNo"].(float64))
	skip := pageSize * (pageNum - 1)
	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	logs := node.mongo.GetPageWarningLogsByUserNameAndTimestampFromDatabase(res["UserName"].(string), start, end, skip, pageSize)
	total := node.mongo.GetPageWarningLogsCountByUserNameAndTimestampFromDatabase(res["UserName"].(string), start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按时间和用户名分页获取告警日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageNormalLogsByIdentityforFE(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNo"] == nil || res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNo"].(float64))
	skip := pageSize * (pageNum - 1)

	logs := node.mongo.GetPageNormalLogsByIdentityFromDatabase(res["IdentityIdentifier"].(string), skip, pageSize)
	total := node.mongo.GetPageNormalLogsCountByIdentityFromDatabase(res["IdentityIdentifier"].(string))

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按身份分页获取正常日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageWarningLogsByIdentityforFE(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNo"] == nil || res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNo"].(float64))
	skip := pageSize * (pageNum - 1)

	logs := node.mongo.GetPageWarningLogsByIdentityFromDatabase(res["IdentityIdentifier"].(string), skip, pageSize)
	total := node.mongo.GetPageWarningLogsCountByIdentityFromDatabase(res["IdentityIdentifier"].(string))

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按身份分页获取告警日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageNormalLogsByIdentityAndTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["PageSize"] == nil || res["PageNo"] == nil || res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNo"].(float64))
	skip := pageSize * (pageNum - 1)
	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	logs := node.mongo.GetPageNormalLogsByIdentityAndTimestampFromDatabase(res["IdentityIdentifier"].(string), start, end, skip, pageSize)
	total := node.mongo.GetPageNormalLogsCountByIdentityAndTimestampFromDatabase(res["IdentityIdentifier"].(string), start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按时间和身份分页获取正常日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetPageWarningLogsByIdentityAndTimestampforFE(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["PageSize"] == nil || res["PageNo"] == nil || res["IdentityIdentifier"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNo"].(float64))
	skip := pageSize * (pageNum - 1)
	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	logs := node.mongo.GetPageWarningLogsByIdentityAndTimestampFromDatabase(res["IdentityIdentifier"].(string), start, end, skip, pageSize)
	total := node.mongo.GetPageWarningLogsCountByIdentityAndTimestampFromDatabase(res["IdentityIdentifier"].(string), start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "按时间和身份分页获取告警日志成功"
	response.Data = logdata
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNumAndListByYearOfNormal(res map[string]interface{}, conn net.Conn) {
	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseByYear()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取近一年内每个月的正常日志数量和列表成功"
	response.Data = analysis
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNumAndListByYearOfWarning(res map[string]interface{}, conn net.Conn) {
	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseByYear()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取近一年内每个月的告警日志数量和列表成功"
	response.Data = analysis
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNumAndListByMonthOfNormal(res map[string]interface{}, conn net.Conn) {
	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseByMonth()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取近一月内每天的正常日志数量和列表成功"
	response.Data = analysis
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNumAndListByMonthOfWarning(res map[string]interface{}, conn net.Conn) {
	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseByMonth()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取近一月内每天的告警日志数量和列表成功"
	response.Data = analysis
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNumAndListByDayOfNormal(res map[string]interface{}, conn net.Conn) {
	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseByDay()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取近一天内每小时的正常日志数量和列表成功"
	response.Data = analysis
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNumAndListByDayOfWarning(res map[string]interface{}, conn net.Conn) {
	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseByDay()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取近一天内每小时的告警日志数量和列表成功"
	response.Data = analysis
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetUGroupLogNumByUGroupIDforMIS(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["UGroupID"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	normLogNum := node.mongo.GetAllNormalLogsCountByGroupIDAndTimestampFromDatabase(res["UGroupID"].(int), start, end)
	warnLogNum := node.mongo.GetAllWarningLogsCountByGroupIDAndTimestampFromDatabase(res["UGroupID"].(int), start, end)

	var response CommonResponse
	logdata := LogNum{NormLogNum: normLogNum, WarnLogNum: warnLogNum}

	response.Code = code.SUCCESS
	response.Message = "按UGroupID获取日志信息成功"
	response.Data = logdata

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNormalLogsAnalysisforMIS(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["Num"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	dur := int(res["Num"].(float64))

	var analysis []int
	analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseDaysOrMonth(start, end, dur)
	/*
		if dur >= 28 || dur <= 31 {
			analysis = node.mongo.GetNormalLogsAnalysisFromDatabase(start, end, dur)
		} else if dur == 12 {
			analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonth()
		}
	*/

	var response CommonResponse

	response.Code = code.SUCCESS
	response.Message = "获取时段内正常日志分析成功"
	response.Data = analysis

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetWarningLogsAnalysisforMIS(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["Num"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	dur := int(res["Num"].(float64))

	var analysis []int
	analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseDaysOrMonth(start, end, dur)
	/*
		if dur >= 28 || dur <= 31 {
			analysis = node.mongo.GetWarningLogsAnalysisFromDatabase(start, end, dur)
		} else if dur == 12 {
			analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonth()
		}
	*/

	var response CommonResponse

	response.Code = code.SUCCESS
	response.Message = "获取时段内告警日志分析成功"
	response.Data = analysis

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetNormalLogsAnalysisByUGroupIDforMIS(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["Num"] == nil || res["UGroupID"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	dur := int(res["Num"].(float64))
	uid := int(res["UGroupID"].(float64))

	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseDaysOrMonthByUGroupID(start, end, dur, uid)

	var response CommonResponse

	response.Code = code.SUCCESS
	response.Message = "按UGroupID获取时段内正常日志分析成功"
	response.Data = analysis

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetWarningLogsAnalysisByUGroupIDforMIS(res map[string]interface{}, conn net.Conn) {
	if res["BeginTime"] == nil || res["EndTime"] == nil || res["Num"] == nil || res["UGroupID"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}

	start := res["BeginTime"].(string)
	end := res["EndTime"].(string)
	dur := int(res["Num"].(float64))
	uid := int(res["UGroupID"].(float64))

	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseDaysOrMonthByUGroupID(start, end, dur, uid)

	var response CommonResponse

	response.Code = code.SUCCESS
	response.Message = "按UGroupID获取时段内正常日志分析成功"
	response.Data = analysis

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error("回复数据解析失败")
		response.Code = code.BAD_REQUEST
		response.Message = "回复数据解析失败"
		response.Data = nil
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

//func (node *Node) GetPageDangerousLogByIdentity(res map[string]interface{}, conn net.Conn) {
//	if res["Username"] == nil || res["PageSize"] == nil || res["PageNum"] == nil {
//		return
//	}
//	pageSize := int(res["PageSize"].(float64))
//	pageNUm := int(res["PageNum"].(float64))
//	skip := pageSize * (pageNUm - 1)
//	logs := node.mongo.GetPageLogsByIdentityIdentifierFromDatabase(res["Username"].(string), skip, pageSize, DangerousLevel)
//	total := node.mongo.GetPageLogsCountByIdentityIdentifierFromDatabase(res["Username"].(string), skip, pageSize, DangerousLevel)
//	var response CommonResponse
//	response.Code = code.SUCCESS
//	response.Message = strconv.Itoa(total)
//	response.Data = logs
//	data, err := json.Marshal(response)
//	if err != nil {
//		fmt.Println(err)
//	}
//	Network.SendResponse(conn, data, res["Key"].(string))
//}
//
//func (node *Node) GetPageDangerousLogByTimestamp(res map[string]interface{}, conn net.Conn) {
//	if res["Start"] == nil || res["End"] == nil || res["PageSize"] == nil || res["PageNum"] == nil {
//		return
//	}
//	start := res["Start"].(string)
//	end := res["End"].(string)
//	pageSize := int(res["PageSize"].(float64))
//	pageNUm := int(res["PageNum"].(float64))
//	skip := pageSize * (pageNUm - 1)
//
//	logs := node.mongo.GetPageLogsByRangeTimeFromDatabase(start, end, skip, pageSize, DangerousLevel)
//	total := node.mongo.GetPageLogsCountByRangeTimeFromDatabase(start, end, skip, pageSize, DangerousLevel)
//
//	var response CommonResponse
//	response.Code = 200
//	response.Message = strconv.Itoa(total)
//	response.Data = logs
//	data, err := json.Marshal(response)
//	if err != nil {
//		fmt.Println(err)
//	}
//	Network.SendResponse(conn, data, res["SecretKey"].(string))
//}

func (node *Node) SendBGMsgOfCertainHeightToFrontend(res map[string]interface{}, conn net.Conn) {
	if res["Height"] == nil {
		return
	}
	common.Logger.Info("MISGetBlockGroup", res["Height"])
	bg := node.mongo.GetBlockFromDatabase(int(res["Height"].(float64)))

	if bg.Height > 0 {
		for x, eachBlock := range bg.Blocks {
			for _, eachTransaction := range eachBlock.Transactions {
				transactionHeader, transactionInterface := MetaData.DecodeTransaction(eachTransaction)
				switch transactionHeader.TXType {
				case MetaData.IdentityAction:
					if transaction, ok := transactionInterface.(*MetaData.Identity); ok {
						data, _ := json.Marshal(transaction)
						bg.Blocks[x].Transactions_s = append(bg.Blocks[x].Transactions_s, string(data))
					}
				case MetaData.UserLogOperation:
					if transaction, ok := transactionInterface.(*MetaData.UserLog); ok {
						data, _ := json.Marshal(transaction)
						bg.Blocks[x].Transactions_s = append(bg.Blocks[x].Transactions_s, string(data))
					}
				case MetaData.CRSRecordOperation:
					if transaction, ok := transactionInterface.(*MetaData.CrsChainRecord); ok {
						data, _ := json.Marshal(transaction)
						bg.Blocks[x].Transactions_s = append(bg.Blocks[x].Transactions_s, string(data))
					}
				}
			}
		}
	} else if bg.Height == 0 {
		if len(bg.Blocks) != 0 {
			if bg.Blocks[0].Height == 0 {
				transactionHeader, transactionInterface := MetaData.DecodeTransaction(bg.Blocks[0].Transactions[0])
				if transactionHeader.TXType == MetaData.Genesis {
					if genesisTransaction, ok := transactionInterface.(*MetaData.GenesisTransaction); ok {
						data, _ := json.Marshal(genesisTransaction)
						bg.Blocks[0].Transactions_s = append(bg.Blocks[0].Transactions_s, string(data))
					}
				}
			}
		}
	}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取该高度的区块组成功"
	response.Data = bg

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

type BCStatusMsgToFrontend struct {
	Agree    float64           `json:"agree"`
	NoState  float64           `json:"no_state"`
	Disagree float64           `json:"disagree"`
	Nodeinfo []MetaData.BCNode `json:"nodeinfo"`
}

func (node *Node) SendBCNodeStatusToFrontend(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	var info BCStatusMsgToFrontend
	if node.config.CacheTime == 0 {
		info.Agree = node.BCStatus.Agree
		info.NoState = node.BCStatus.NoState
		info.Disagree = node.BCStatus.Disagree
		info.Nodeinfo = node.BCStatus.Nodes
	} else {
		var bs = node.mongo.GetBCStatusFromDatabase()
		info.Agree = bs.Agree
		info.NoState = bs.NoState
		info.Disagree = bs.Disagree
		info.Nodeinfo = bs.Nodeinfo
	}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取节点状态信息成功"
	response.Data = info

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))
}

type BCRolesProportionMsgToFrontend struct {
	Com        int `json:"com"`
	Butler     int `json:"butler"`
	Butlernext int `json:"butlernext"`
}

func (node *Node) GetRolesProportion(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	var info BCRolesProportionMsgToFrontend
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	var num1, num2, num3 = 0, 0, 0
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Is_commissioner == true {
			num1++
		}
		if roleinfo[i].Is_butler == true {
			num2++
		}
		if roleinfo[i].Is_butler_candidate == true {
			num3++
		}
	}
	info.Com = num1
	info.Butler = num2
	info.Butlernext = num3

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取节点角色数量信息成功"
	response.Data = info

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetListButlernext(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	butlernext := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Is_butler_candidate == true {
			butlernext = append(butlernext, roleinfo[i])
		}
	}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取候选管家列表信息成功"
	response.Data = butlernext

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))

}

func (node *Node) GetListButler(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	butler := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Is_butler == true {
			butler = append(butler, roleinfo[i])
		}
	}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取管家列表信息成功"
	response.Data = butler

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))

}

func (node *Node) GetListCom(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	com := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Is_commissioner == true {
			com = append(com, roleinfo[i])
		}
	}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取委员列表信息成功"
	response.Data = com

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))
}

type BCStatusProportionMsgToFrontend struct {
	Normal   int `json:"normal"`
	Abnormal int `json:"abnormal"`
}

func (node *Node) GetStatusProportion(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	var info BCStatusProportionMsgToFrontend
	var bs = node.BCStatus
	info.Normal = int((bs.Agree + bs.Disagree)) * len(bs.Nodes)
	info.Abnormal = int(bs.NoState) * len(bs.Nodes)

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取正常、异常节点数量信息成功"
	response.Data = info

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetStatusNormalList(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	nl := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Agreement == -1 || roleinfo[i].Agreement == 1 {
			nl = append(nl, roleinfo[i])
		}
	}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取正常节点列表信息成功"
	response.Data = nl

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) GetStatusAbnormalList(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	anl := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Agreement != -1 && roleinfo[i].Agreement != 1 {
			anl = append(anl, roleinfo[i])
		}
	}

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取异常节点列表信息成功"
	response.Data = anl

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	node.BCStatus.Mutex.RUnlock()
	Network.SendResponse(conn, data, res["Key"].(string))
}

// GetBlockInfByPage 按页获取区块的所有信息
//
// @Description: 按页获取区块的所有信息
// @receiver node
// @param res
// @param conn
//
func (node *Node) GetBlockInfByPage(res map[string]interface{}, conn net.Conn) {
	if res["PageSize"] == nil || res["PageNum"] == nil {
		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
		data, err := json.Marshal(resp)
		if err != nil {
			common.Logger.Error(err)
		}
		Network.SendResponse(conn, data, res["Key"].(string))
		return
	}
	pageSize := int(res["PageSize"].(float64))
	pageNum := int(res["PageNum"].(float64))
	skip := pageSize * (pageNum - 1)

	bgs := node.mongo.GetPageBlockFromDatabase(skip, pageSize)

	for _, bg := range bgs {
		if bg.Height > 0 {
			for x, eachBlock := range bg.Blocks {
				for _, eachTransaction := range eachBlock.Transactions {
					transactionHeader, transactionInterface := MetaData.DecodeTransaction(eachTransaction)
					switch transactionHeader.TXType {
					case MetaData.IdentityAction:
						if transaction, ok := transactionInterface.(*MetaData.Identity); ok {
							data, _ := json.Marshal(transaction)
							bg.Blocks[x].Transactions_s = append(bg.Blocks[x].Transactions_s, string(data))
						}
					case MetaData.UserLogOperation:
						if transaction, ok := transactionInterface.(*MetaData.UserLog); ok {
							data, _ := json.Marshal(transaction)
							bg.Blocks[x].Transactions_s = append(bg.Blocks[x].Transactions_s, string(data))
						}
					case MetaData.CRSRecordOperation:
						if transaction, ok := transactionInterface.(*MetaData.CrsChainRecord); ok {
							data, _ := json.Marshal(transaction)
							bg.Blocks[x].Transactions_s = append(bg.Blocks[x].Transactions_s, string(data))
						}
					}
				}
			}
		} else if bg.Height == 0 {
			if len(bg.Blocks) != 0 {
				if bg.Blocks[0].Height == 0 {
					transactionHeader, transactionInterface := MetaData.DecodeTransaction(bg.Blocks[0].Transactions[0])
					if transactionHeader.TXType == MetaData.Genesis {
						if genesisTransaction, ok := transactionInterface.(*MetaData.GenesisTransaction); ok {
							data, _ := json.Marshal(genesisTransaction)
							bg.Blocks[0].Transactions_s = append(bg.Blocks[0].Transactions_s, string(data))
						}
					}
				}
			}
		}
	}

	var response CommonResponse
	var message PageBlockGroupInf

	message.Blockgroups = bgs
	message.Total = len(bgs)

	response.Code = code.SUCCESS
	response.Message = "获取分页区块组信息成功"
	response.Data = message
	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}
	Network.SendResponse(conn, data, res["Key"].(string))
}

type BCOverviewInfo struct {
	Height   int64  `json:"height"`
	Total    uint64 `json:"total"`
	Handling uint64 `json:"handling"`
	NodeNum  int    `json:"nodenum"`
}

func (node *Node) getOverviewInfo(res map[string]interface{}, conn net.Conn) {
	node.BCStatus.Mutex.RLock()
	var info BCOverviewInfo
	info.Height = node.BCStatus.Overview.Height
	info.Total = node.BCStatus.Overview.TransactionNum
	info.Handling = node.BCStatus.Overview.ProcessingTransactionNum
	info.NodeNum = node.BCStatus.Overview.NodeNum
	node.BCStatus.Mutex.RUnlock()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取区块链状态概要信息成功"
	response.Data = info

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) getTransactionAnalysis(res map[string]interface{}, conn net.Conn) {
	var txsnum []uint64
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.TxsNumList.Front(); i != nil; i = i.Next() {
		txsnum = append(txsnum, (i.Value).(uint64))
	}
	node.BCStatus.Mutex.RUnlock()

	var response CommonResponse
	response.Code = code.SUCCESS
	response.Message = "获取区块链近15天交易量成功"
	response.Data = txsnum

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) getLastBlocksInfo(res map[string]interface{}, conn net.Conn) {
	var response CommonResponse

	var bgs []interface{}
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.BgsList.Front(); i != nil; i = i.Next() {
		bgs = append(bgs, i.Value)
	}
	node.BCStatus.Mutex.RUnlock()

	response.Code = code.SUCCESS
	response.Message = "获取最近10个区块组成功"
	response.Data = bgs

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

func (node *Node) getLastTransactionsInfo(res map[string]interface{}, conn net.Conn) {
	var response CommonResponse

	var txs []interface{}
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.TxsList.Front(); i != nil; i = i.Next() {
		txs = append(txs, i.Value)
	}
	node.BCStatus.Mutex.RUnlock()

	response.Code = code.SUCCESS
	response.Message = "获取最近10个交易成功"
	response.Data = txs

	data, err := json.Marshal(response)
	if err != nil {
		common.Logger.Error(err)
	}

	Network.SendResponse(conn, data, res["Key"].(string))
}

// CertRevocation 证书撤销
//
// @Description: 由超级管理员来进行证书撤销操作
// @receiver node
// @param res
// @param conn
//
//func (node *Node) CertRevocation(res map[string]interface{}, conn net.Conn) {
//	if res["IdentityIdentifier"] == nil {
//		resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
//		data, err := json.Marshal(resp)
//		if err != nil {
//			common.Logger.Error(err)
//		}
//		Network.SendResponse(conn, data, res["Key"].(string))
//		return
//	}
//	var response CommonResponse
//
//	if node.mongo.HasIdentityData("identityidentifier", res["IdentityIdentifier"].(string)) {
//		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", res["IdentityIdentifier"].(string))
//		if identity.IsValid == code.PENDING_REVIEW || identity.IsValid == code.WITHOUT_CERT{
//			resp := CommonResponse{Code: code.BAD_REQUEST, Message: "This identity is lack of cert", Data: nil}
//			data, err := json.Marshal(resp)
//			if err != nil {
//				common.Logger.Error(err)
//			}
//			Network.SendResponse(conn, data, res["Key"].(string))
//			return
//		}else if identity.IsValid == code.VALID{
//			resp := CommonResponse{Code: code.FORBIDDEN, Message: "This identity needs to be disabled first", Data: nil}
//			data, err := json.Marshal(resp)
//			if err != nil {
//				common.Logger.Error(err)
//			}
//			Network.SendResponse(conn, data, res["Key"].(string))
//			return
//		}else if identity.IsValid == code.INVALID{
//			var transaction MetaData.Identity
//			transaction.Type = res["Type"].(string)
//			transaction.Command = res["Command"].(string)
//			transaction.IdentityIdentifier = res["IdentityIdentifier"].(string)
//
//			var transactionHeader MetaData.TransactionHeader
//			transactionHeader.TXType = MetaData.IdentityAction
//			node.txPool.PushbackTransaction(transactionHeader, &transaction)
//		}
//		node.mongo.UpdateIdentityModifyRecords(res)
//		response.Code = code.SUCCESS
//		response.Message = "申请注销成功"
//		response.Data = nil
//	} else {
//		response.Code = code.NOT_FOUND
//		response.Message = "数据库不存在该用户"
//		response.Data = nil
//	}
//
//	data, err := json.Marshal(response)
//	if err != nil {
//		common.Logger.Error(err)
//	}
//	Network.SendResponse(conn, data, res["Key"].(string))
//}
