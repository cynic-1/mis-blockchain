package Node

import (
	"MIS-BC/MetaData"
	"MIS-BC/common"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

type crsPool struct {
	crsChan chan interface{}
	crsPool sync.Pool
}

func (node *Node) HandleCRSMessage(v *gin.RouterGroup) {
	// ping 测试路由
	v.GET("/ping", node.ping)
	// 存储crs上传至MIS的记录的路由
	v.POST("/upload", node.upload)

	// 获取特定高度的区块信息
	v.GET("getBGMsgOfCertainHeightFromServer", node.sendBGMsgOfCertainHeightToFrontend)
	// 获取当前区块链状态信息
	v.GET("getBCNodeStatusMsgFromServer", node.sendBCNodeStatusToFrontend)
	// 获取节点角色分布
	v.GET("getRolesProportion", node.getRolesProportion)
	// 获取下一任轮值记账节点
	v.GET("getListButlernext", node.getListButlernext)
	// 获取轮值记账节点
	v.GET("getListButler", node.getListButler)
	// 获取管家节点
	v.GET("getListCom", node.getListCom)

	// 获取节点状态分布
	v.GET("getStatusProportion", node.getStatusProportion)
	// 获取正常节点列表
	v.GET("getStatusNormalList", node.getStatusNormalList)
	// 获取恶意节点列表
	v.GET("getStatusAbnormalList", node.getStatusAbnormalList)
	// 获取分页区块信息
	v.GET("getBlockInfByPage", node.getBlockInfByPage)

	// 获取MIS概览信息
	v.GET("getOverviewInfo", node.getOverviewInfoforCRS)
	// 获取交易统计列表
	v.GET("getTransactionAnalysis", node.getTransactionAnalysisforCRS)
	// 获取最近的多个区块链组信息
	v.GET("getLastBGsInfo", node.getLastBlocksInfoforCRS)
	// 获取最近的多个交易信息
	v.GET("getLastTransactionsInfo", node.getLastTransactionsInfoforCRS)

	// 日志测试
	v.GET("getAllNormalLogsByTimestamp", node.getAllNormalLogsByTimestampforCRS)
	v.GET("getPageNormalLogsByTimestamp", node.getPageNormalLogsByTimestampforCRS)
	v.GET("getAllWarningLogsByTimestamp", node.getAllWarningLogsByTimestampforCRS)
	v.GET("getPageWarningLogsByTimestamp", node.GetPageWarningLogsByTimestampforCRS)
	v.GET("getNumAndListByYearOfNormal", node.GetNumAndListByYearOfNormalforCRS)
	v.GET("getNumAndListByYearOfWarning", node.GetNumAndListByYearOfWarningforCRS)
	v.GET("getNumAndListByMonthOfNormal", node.GetNumAndListByMonthOfNormalforCRS)
	v.GET("getNumAndListByMonthOfWarning", node.GetNumAndListByMonthOfWarningforCRS)
	v.GET("getNumAndListByDayOfNormal", node.GetNumAndListByDayOfNormalforCRS)
	v.GET("getNumAndListByDayOfWarning", node.GetNumAndListByDayOfWarningforCRS)
	v.GET("getNormalLogsAnalysis", node.GetNormalLogsAnalysisforCRS)
	v.GET("getWarningLogsAnalysis", node.GetWarningLogsAnalysisforCRS)

	// 身份测试
	v.GET("getAllIdentityAllInf", node.GetAllIdentityAllInfforCRS)
	v.GET("getAllIdentityAllInfByPage", node.GetAllIdentityAllInfByPageforCRS)
	v.GET("getAllPendingIdentity", node.GetAllPendingIdentityforCRS)
	v.GET("getAllPendingIdentityByPage", node.GetAllPendingIdentityByPageforCRS)
	v.GET("getAllCheckedIdentity", node.GetAllCheckedIdentityforCRS)
	v.GET("getAllCheckedIdentityByPage", node.GetAllCheckedIdentityByPageforCRS)
	v.GET("getNumOfIdentityByStatus", node.GetNumOfIdentityByStatusforCRS)
	v.GET("getAllActionsByIdentityIdentifierAndPage", node.GetAllActionsByIdentityIdentifierAndPageforCRS)
	v.GET("getAllActionsByIdentityIdentifier", node.GetAllActionsByIdentityIdentifierforCRS)
	v.GET("getAllWithoutCertIdentityByPage", node.GetAllWithoutCertIdentityByPageforCRS)
	v.GET("getAllAbledIdentityByPage", node.GetAllAbledIdentityByPageforCRS)
	v.GET("getAllDisabledIdentityByPage", node.GetAllDisabledIdentityByPageforCRS)
}

func (node *Node) ping(c *gin.Context) {
	c.String(http.StatusOK, "ping")
}

func (node *Node) upload(c *gin.Context) {
	record := node.CRSItemPool.crsPool.Get().(*MetaData.CrsChainRecord)

	err := c.BindJSON(&record)
	if err != nil {
		common.Logger.Error("解析crs record失败", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
	}
	if node.UploadCRSRecord(record) == nil {
		c.JSON(http.StatusOK, gin.H{"error": nil})
	}
	node.CRSItemPool.crsPool.Put(record)
}

func (node *Node) UploadCRSRecord(record *MetaData.CrsChainRecord) error {
	transaction := node.CRSItemPool.crsPool.Get().(*MetaData.CrsChainRecord)
	transaction.Data = record.Data
	transaction.BlockHash = record.BlockHash
	transaction.TransactionHash = record.TransactionHash
	transaction.EntId = record.EntId
	transaction.CreateTime = record.CreateTime
	transaction.BelongTo = record.BelongTo

	node.CRSItemPool.crsChan <- transaction
	node.CRSItemPool.crsPool.Put(transaction)
	return nil
}

func (node *Node) StartUploadCRSRecordServer() error {
	defer func() {
		if err := recover(); err != nil {
			common.Logger.Error("panic when program execute,err:", err)
			debug.PrintStack()
		}
	}()

	for {
		select {
		case record := <-node.CRSItemPool.crsChan:
			var transactionHeader MetaData.TransactionHeader
			transactionHeader.TXType = MetaData.CRSRecordOperation
			common.Logger.Info(record.(*MetaData.CrsChainRecord).Data, " 正在申请上传")
			r := node.txPool.PushbackTransaction(transactionHeader, record.(*MetaData.CrsChainRecord))
			if r == -1 {
				return errors.New("CRS记录放入事务池失败")
			}
		}
	}
}

func (node *Node) SendHeightofBlock(height int, serialNumber uint32, transactionHash string) (*http.Response, error) {
	bodyJson, _ := json.Marshal(map[string]interface{}{
		"height":          height,
		"serialNumber":    serialNumber,
		"transactionHash": transactionHash,
	})

	r, err := http.DefaultClient.Post(
		"http://118.24.6.91:8201"+"/api/v1/crs/chainRecord/set?transactionHash="+transactionHash+"&height="+
			strconv.Itoa(height)+"&serialNumber="+strconv.Itoa(int(serialNumber)),
		"application/json",
		strings.NewReader(string(bodyJson)),
	)

	if err != nil {
		common.Logger.Error("sendHeight err: ", err)
	} else {
		common.Logger.Info("sendHeight respond: ", r.Body)
	}

	return r, err
}

func (node *Node) getBGMsgOfCertainHeightFromServer(c *gin.Context) {
	record := node.CRSItemPool.crsPool.Get().(*MetaData.CrsChainRecord)

	err := c.BindJSON(&record)
	if err != nil {
		common.Logger.Error("解析crs record失败", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
	}
	if node.UploadCRSRecord(record) == nil {
		c.JSON(http.StatusOK, gin.H{"error": nil})
	}
	node.CRSItemPool.crsPool.Put(record)
}

type feRequest struct {
	Height int `msg:"height"`
}

func (node *Node) sendBGMsgOfCertainHeightToFrontend(c *gin.Context) {
	height, error := strconv.Atoi(c.Query("height"))
	if error != nil {
		panic(error)
	}
	bg := node.mongo.GetBlockFromDatabase(height)

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

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": bg})

}

//type BCStatusMsgToFrontend struct {
//	Agree    float64           `json:"agree"`
//	NoState  float64           `json:"no_state"`
//	Disagree float64           `json:"disagree"`
//	Nodeinfo []MetaData.BCNode `json:"nodeinfo"`
//}

func (node *Node) sendBCNodeStatusToFrontend(c *gin.Context) {
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

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": info})

	node.BCStatus.Mutex.RUnlock()
}

//type BCRolesProportionMsgToFrontend struct {
//	Com        int `json:"com"`
//	Butler     int `json:"butler"`
//	Butlernext int `json:"butlernext"`
//}

func (node *Node) getRolesProportion(c *gin.Context) {
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

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": info})

	node.BCStatus.Mutex.RUnlock()
}

func (node *Node) getListButlernext(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	butlernext := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Is_butler_candidate == true {
			butlernext = append(butlernext, roleinfo[i])
		}
	}

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": butlernext})

	node.BCStatus.Mutex.RUnlock()

}

func (node *Node) getListButler(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	butler := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Is_butler == true {
			butler = append(butler, roleinfo[i])
		}
	}

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": butler})

	node.BCStatus.Mutex.RUnlock()
}

func (node *Node) getListCom(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	com := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Is_commissioner == true {
			com = append(com, roleinfo[i])
		}
	}

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": com})

	node.BCStatus.Mutex.RUnlock()
}

func (node *Node) getStatusProportion(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	var info BCStatusProportionMsgToFrontend
	var bs = node.BCStatus
	info.Normal = int((bs.Agree + bs.Disagree)) * len(bs.Nodes)
	info.Abnormal = int(bs.NoState) * len(bs.Nodes)

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": info})

	node.BCStatus.Mutex.RUnlock()
}

func (node *Node) getStatusNormalList(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	nl := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Agreement == -1 || roleinfo[i].Agreement == 1 {
			nl = append(nl, roleinfo[i])
		}
	}

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": nl})

	node.BCStatus.Mutex.RUnlock()
}

func (node *Node) getStatusAbnormalList(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	//var bs = node.mongo.GetBCStatusFromDatabase()
	var roleinfo = node.BCStatus.Nodes
	anl := make([]MetaData.BCNode, len(roleinfo))
	for i := 0; i < len(roleinfo); i++ {
		if roleinfo[i].Agreement != -1 && roleinfo[i].Agreement != 1 {
			anl = append(anl, roleinfo[i])
		}
	}

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": anl})

	node.BCStatus.Mutex.RUnlock()
}

type BlockInfRequest struct {
	PageSize int `msg:"PageSize"`
	PageNum  int `msg:"PageNum"`
}

// GetBlockInfByPage 按页获取区块的所有信息
//
// @Description: 按页获取区块的所有信息
// @receiver node
// @param res
// @param conn
//
func (node *Node) getBlockInfByPage(c *gin.Context) {
	//res := BlockInfRequest{}

	// err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}
	//if res["PageSize"] == nil || res["PageNum"] == nil {
	//	resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
	//	data, err := json.Marshal(resp)
	//	if err != nil {
	//		common.Logger.Error(err)
	//	}
	//	Network.SendResponse(conn, data, res["Key"].(string))
	//	return
	//}
	pageSize, error := strconv.Atoi(c.Query("PageSize"))
	if error != nil {
		panic(error)
	}
	pageNum, error := strconv.Atoi(c.Query("PageNum"))
	if error != nil {
		panic(error)
	}
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

	common.Logger.Info("分页获取区块组信息：", bgs)
	var message PageBlockGroupInf

	message.Blockgroups = bgs
	message.Total = len(bgs)

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": message})
}

//type BCOverviewInfo struct {
//	Height   int64  `json:"height"`
//	Total    uint64 `json:"total"`
//	Handling uint64 `json:"handling"`
//	NodeNum  int    `json:"nodenum"`
//}

func (node *Node) getOverviewInfoforCRS(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	var info BCOverviewInfo
	info.Height = node.BCStatus.Overview.Height
	info.Total = node.BCStatus.Overview.TransactionNum
	info.Handling = node.BCStatus.Overview.ProcessingTransactionNum
	info.NodeNum = node.BCStatus.Overview.NodeNum
	node.BCStatus.Mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": info})
}

func (node *Node) getTransactionAnalysisforCRS(c *gin.Context) {
	var txsnum []uint64
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.TxsNumList.Front(); i != nil; i = i.Next() {
		txsnum = append(txsnum, (i.Value).(uint64))
	}
	node.BCStatus.Mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": txsnum})
}

func (node *Node) getLastBlocksInfoforCRS(c *gin.Context) {
	var bgs []interface{}
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.BgsList.Front(); i != nil; i = i.Next() {
		bgs = append(bgs, i.Value)
	}
	node.BCStatus.Mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": bgs})

}

func (node *Node) getLastTransactionsInfoforCRS(c *gin.Context) {
	var txs []interface{}
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.TxsList.Front(); i != nil; i = i.Next() {
		txs = append(txs, i.Value)
	}
	node.BCStatus.Mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": txs})
}

type timestampRequest struct {
	BeginTime          string `msg:"BeginTime"`
	EndTime            string `msg:"EndTime"`
	PageSize           int    `msg:"PageSize"`
	PageNo             int    `msg:"PageNo"`
	IdentityIdentifier string `msg:"IdentityIdentifier"`
}

func (node *Node) getAllNormalLogsByTimestampforCRS(c *gin.Context) {
	//res := timestampRequest{}

	start := c.Query("BeginTime")
	end := c.Query("EndTime")
	logs := node.mongo.GetNormalLogsByTimestampFromDatabase(start, end)
	total := node.mongo.GetNormalLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": logdata})
}

func (node *Node) getPageNormalLogsByTimestampforCRS(c *gin.Context) {

	if c.Query("IdentityIdentifier") == "" {
		pageSize, error := strconv.Atoi(c.Query("PageSize"))
		if error != nil {
			panic(error)
		}
		pageNum, error := strconv.Atoi(c.Query("PageNo"))
		if error != nil {
			panic(error)
		}
		skip := pageSize * (pageNum - 1)
		start := c.Query("BeginTime")
		end := c.Query("EndTime")

		logs := node.mongo.GetPageNormalLogsByTimestampFromDatabase(start, end, skip, pageSize)
		total := node.mongo.GetPageNormalLogsCountByTimestampFromDatabase(start, end)

		logdata := PageUserlogRespond{Logs: logs, Count: total}

		c.JSON(http.StatusOK, gin.H{"error": nil, "data": logdata})
	} else if c.Query("IdentityIdentifier") != "" {
		pageSize, error := strconv.Atoi(c.Query("PageSize"))
		if error != nil {
			panic(error)
		}
		pageNum, error := strconv.Atoi(c.Query("PageNo"))
		if error != nil {
			panic(error)
		}
		skip := pageSize * (pageNum - 1)
		start := c.Query("BeginTime")
		end := c.Query("EndTime")

		logs := node.mongo.GetPageNormalLogsByTimestampAndIdentifierFromDatabase(start, end, c.Query("IdentityIdentifier"), skip, pageSize)
		total := node.mongo.GetPageNormalLogsCountByTimestampAndIdentifierFromDatabase(start, end, c.Query("IdentityIdentifier"))

		logdata := PageUserlogRespond{Logs: logs, Count: total}

		c.JSON(http.StatusOK, gin.H{"error": nil, "data": logdata})
	}
}

func (node *Node) getAllWarningLogsByTimestampforCRS(c *gin.Context) {
	//res := timestampRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}

	start := c.Query("BeginTime")
	end := c.Query("EndTime")
	logs := node.mongo.GetAllWarningLogsByTimestampFromDatabase(start, end)
	total := node.mongo.GetAllWarningLogsCountByTimestampFromDatabase(start, end)

	logdata := PageUserlogRespond{Logs: logs, Count: total}

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": logdata})
}

func (node *Node) GetPageWarningLogsByTimestampforCRS(c *gin.Context) {
	//res := timestampRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//	return
	//}
	if c.Query("IdentityIdentifier") == "" {
		pageSize, error := strconv.Atoi(c.Query("PageSize"))
		if error != nil {
			panic(error)
		}
		pageNum, error := strconv.Atoi(c.Query("PageNo"))
		if error != nil {
			panic(error)
		}
		skip := pageSize * (pageNum - 1)
		start := c.Query("BeginTime")
		end := c.Query("EndTime")

		logs := node.mongo.GetPageWarningLogsByTimestampFromDatabase(start, end, skip, pageSize)
		total := node.mongo.GetPageWarningLogsCountByTimestampFromDatabase(start, end)
		logdata := PageUserlogRespond{Logs: logs, Count: total}
		c.JSON(http.StatusOK, gin.H{"error": nil, "data": logdata, "message": "按时间分页获取所有告警日志成功"})
	} else if c.Query("IdentityIdentifier") != "" {
		pageSize, error := strconv.Atoi(c.Query("PageSize"))
		if error != nil {
			panic(error)
		}
		pageNum, error := strconv.Atoi(c.Query("PageNo"))
		if error != nil {
			panic(error)
		}
		skip := pageSize * (pageNum - 1)
		start := c.Query("BeginTime")
		end := c.Query("EndTime")

		logs := node.mongo.GetPageWarningLogsByTimestampAndIdentifierFromDatabase(start, end, c.Query("IdentityIdentifier"), skip, pageSize)
		total := node.mongo.GetPageWarningLogsCountByTimestampAndIdentifierFromDatabase(start, end, c.Query("IdentityIdentifier"))

		logdata := PageUserlogRespond{Logs: logs, Count: total}

		c.JSON(http.StatusOK, gin.H{"error": nil, "data": logdata, "message": "按时间分页获取所有告警日志成功"})
	}
}

func (node *Node) GetNumAndListByYearOfNormalforCRS(c *gin.Context) {
	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseByYear()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取近一年内每个月的正常日志数量和列表成功"})
}

func (node *Node) GetNumAndListByYearOfWarningforCRS(c *gin.Context) {
	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseByYear()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取近一年内每个月的告警日志数量和列表成功"})
}

func (node *Node) GetNumAndListByMonthOfNormalforCRS(c *gin.Context) {
	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseByMonth()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取近一月内每天的正常日志数量和列表成功"})
}

func (node *Node) GetNumAndListByMonthOfWarningforCRS(c *gin.Context) {
	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseByMonth()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取近一月内每天的告警日志数量和列表成功"})
}

func (node *Node) GetNumAndListByDayOfNormalforCRS(c *gin.Context) {
	analysis := node.mongo.GetNormalLogsAnalysisFromDatabaseByDay()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取近一天内每小时的正常日志数量和列表成功"})
}

func (node *Node) GetNumAndListByDayOfWarningforCRS(c *gin.Context) {
	analysis := node.mongo.GetWarningLogsAnalysisFromDatabaseByDay()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取近一天内每小时的告警日志数量和列表成功"})
}

type AnalysisRequest struct {
	BeginTime string `msg:"BeginTime"`
	EndTime   string `msg:"EndTime"`
	Num       int    `msg:"Num"`
}

func (node *Node) GetNormalLogsAnalysisforCRS(c *gin.Context) {
	//res := AnalysisRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//	return
	//}
	dur, error := strconv.Atoi(c.Query("Num"))
	if error != nil {
		panic(error)
	}
	start := c.Query("BeginTime")
	end := c.Query("EndTime")

	var analysis []int
	analysis = node.mongo.GetNormalLogsAnalysisFromDatabaseDaysOrMonth(start, end, dur)

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取时段内正常日志分析成功"})
}

func (node *Node) GetWarningLogsAnalysisforCRS(c *gin.Context) {
	//res := AnalysisRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//	return
	//}

	dur, error := strconv.Atoi(c.Query("Num"))
	if error != nil {
		panic(error)
	}
	start := c.Query("BeginTime")
	end := c.Query("EndTime")

	var analysis []int
	analysis = node.mongo.GetWarningLogsAnalysisFromDatabaseDaysOrMonth(start, end, dur)
	c.JSON(http.StatusOK, gin.H{"error": nil, "data": analysis, "message": "获取时段内告警日志分析成功"})
}

func (node *Node) GetAllIdentityAllInfforCRS(c *gin.Context) {
	identities := node.mongo.GetAllIdentityFromDatabase()
	c.JSON(http.StatusOK, gin.H{"error": nil, "data": identities})
}

type IdentityRequest struct {
	PageSize int `msg:"PageSize"`
	PageNum  int `msg:"PageNum"`
}

// GetAllIdentityAllInfByPage 按页获取身份的所有信息
//
// @Description: 按页获取身份的所有信息
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllIdentityAllInfByPageforCRS(c *gin.Context) {
	//res := IdentityRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}
	pageSize, error := strconv.Atoi(c.Query("PageSize"))
	if error != nil {
		panic(error)
	}
	pageNum, error := strconv.Atoi(c.Query("PageNum"))
	if error != nil {
		panic(error)
	}
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetIdentityCountFromDatabase()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": message})
}

// GetAllPendingIdentity 获取所有待审核的身份
//
// @Description: 获取所有待审核的身份
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllPendingIdentityforCRS(c *gin.Context) {
	identities := node.mongo.GetPendingIdentityFromDatabase()
	c.JSON(http.StatusOK, gin.H{"error": nil, "data": identities})
}

// GetAllPendingIdentityByPage 按页获取所有待审核的身份
//
// @Description: 按页获取所有待审核的身份
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllPendingIdentityByPageforCRS(c *gin.Context) {
	//res := IdentityRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}
	pageSize, error := strconv.Atoi(c.Query("PageSize"))
	if error != nil {
		panic(error)
	}
	pageNum, error := strconv.Atoi(c.Query("PageNum"))
	if error != nil {
		panic(error)
	}
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPagePendingIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetPendingIdentityCountFromDatabase()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": message})
}

// GetAllCheckedIdentity 获取所有已审核的身份
//
// @Description: 获取所有已审核的身份
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllCheckedIdentityforCRS(c *gin.Context) {
	identities := node.mongo.GetCheckedIdentityCountFromDatabase()
	c.JSON(http.StatusOK, gin.H{"error": nil, "data": identities})
}

// GetAllPendingIdentityByPage 按页获取所有待审核的身份
//
// @Description: 按页获取所有待审核的身份
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllCheckedIdentityByPageforCRS(c *gin.Context) {
	//res := IdentityRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}
	pageSize, error := strconv.Atoi(c.Query("PageSize"))
	if error != nil {
		panic(error)
	}
	pageNum, error := strconv.Atoi(c.Query("PageNum"))
	if error != nil {
		panic(error)
	}
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageCheckedIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetCheckedIdentityCountFromDatabase()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": message})
}

// GetAllDisabledIdentityByPage 按页获取所有禁用的身份
//
// @Description: 按页获取所有禁用的身份
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllDisabledIdentityByPageforCRS(c *gin.Context) {
	//res := IdentityRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}
	pageSize, error := strconv.Atoi(c.Query("PageSize"))
	if error != nil {
		panic(error)
	}
	pageNum, error := strconv.Atoi(c.Query("PageNum"))
	if error != nil {
		panic(error)
	}
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageDisabledIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetDisabledIdentityCountFromDatabase()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": message})
}

// GetAllAbledIdentity 按页获取所有正常的身份
//
// @Description: 按页获取所有正常的身份
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllAbledIdentityByPageforCRS(c *gin.Context) {
	//res := IdentityRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}
	pageSize, error := strconv.Atoi(c.Query("PageSize"))
	if error != nil {
		panic(error)
	}
	pageNum, error := strconv.Atoi(c.Query("PageNum"))
	if error != nil {
		panic(error)
	}
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageAbledIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetAbledIdentityCountFromDatabase()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": message})
}

// GetAllWithoutCertIdentityByPage 按页获取所有没有证书的身份
//
// @Description: 按页获取所有没有证书的身份
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllWithoutCertIdentityByPageforCRS(c *gin.Context) {
	//res := IdentityRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}
	pageSize, error := strconv.Atoi(c.Query("PageSize"))
	if error != nil {
		panic(error)
	}
	pageNum, error := strconv.Atoi(c.Query("PageNum"))
	if error != nil {
		panic(error)
	}
	skip := pageSize * (pageNum - 1)

	identities := node.mongo.GetPageWithoutCertIdentityFromDatabase(skip, pageSize)

	var message PageIdentityInf
	message.Identities = identities
	message.Total = node.mongo.GetWithoutCertIdentityCountFromDatabase()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": message})
}

type IdentifierRequest struct {
	PageSize           int    `msg:"PageSize"`
	PageNum            int    `msg:"PageNum"`
	IdentityIdentifier string `msg:"IdentityIdentifier"`
}

// GetAllActionsByIdentityIdentifier 获得某个用户的历史行为信息
//
// @Description: 获得某个用户的历史行为信息
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllActionsByIdentityIdentifierforCRS(c *gin.Context) {
	//res := IdentifierRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}

	if !node.mongo.HasIdentityData("identityidentifier", c.Query("IdentityIdentifier")) {
		c.JSON(http.StatusNotFound, gin.H{"error": nil, "data": MetaData.Identity{}, "message": "不存在该身份"})
	} else {
		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", c.Query("IdentityIdentifier"))
		c.JSON(http.StatusOK, gin.H{"error": nil, "data": identity.ModifyRecords, "message": "成功获得该身份行为信息"})
	}
}

// GetAllActionsByIdentityIdentifierAndPage 获得某个用户的分页历史行为信息
//
// @Description: 获得某个用户的分页历史行为信息
// @receiver node
// @param res
// @param conn
func (node *Node) GetAllActionsByIdentityIdentifierAndPageforCRS(c *gin.Context) {
	//res := IdentifierRequest{}

	//err := c.BindJSON(&res)
	//if err != nil {
	//	common.Logger.Error("解析crs request失败", err.Error())
	//	c.JSON(http.StatusBadRequest, gin.H{"error": err})
	//}

	var data IdentityActionsResponse
	if !node.mongo.HasIdentityData("identityidentifier", c.Query("IdentityIdentifier")) {
		c.JSON(http.StatusNotFound, gin.H{"error": nil, "data": MetaData.Identity{}, "message": "不存在该身份"})
	} else {
		pageSize, error := strconv.Atoi(c.Query("PageSize"))
		if error != nil {
			panic(error)
		}
		pageNum, error := strconv.Atoi(c.Query("PageNum"))
		if error != nil {
			panic(error)
		}
		skip := pageSize * (pageNum - 1)

		identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", c.Query("IdentityIdentifier"))
		l := len(identity.ModifyRecords)
		data.Total = l
		if skip >= l {
			c.JSON(http.StatusBadRequest, gin.H{"error": nil, "data": nil, "message": "超出长度范围"})
		} else if l-skip < pageSize {
			data.Records = identity.ModifyRecords[skip:]
			c.JSON(http.StatusOK, gin.H{"error": nil, "data": data, "message": "成功获得该身份行为信息"})
		} else {
			data.Records = identity.ModifyRecords[skip : skip+pageSize]
			c.JSON(http.StatusOK, gin.H{"error": nil, "data": data, "message": "成功获得该身份行为信息"})
		}
	}
}

// GetNumOfIdentityByStatus 获取禁用、正常、待审核、撤销证书身份数量
//
// @Description: 获取禁用、正常、待审核、撤销证书身份数量
// @receiver node
// @param res
// @param conn
func (node *Node) GetNumOfIdentityByStatusforCRS(c *gin.Context) {
	var m NumOfIdentity
	m.Valid = node.mongo.GetAbledIdentityCountFromDatabase()
	m.InValid = node.mongo.GetDisabledIdentityCountFromDatabase()
	m.Pending = node.mongo.GetPendingIdentityCountFromDatabase()
	m.WithoutCert = node.mongo.GetWithoutCertIdentityCountFromDatabase()

	c.JSON(http.StatusOK, gin.H{"error": nil, "data": m, "message": "获取禁用、正常、待审核、撤销证书身份数量"})
}
