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
	height int
}

func (node *Node) sendBGMsgOfCertainHeightToFrontend(c *gin.Context) {
	res := feRequest{}

	err := c.BindJSON(&res)
	if err != nil {
		common.Logger.Error("解析crs request失败", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
	}

	common.Logger.Info("MISGetBlockGroup", res.height)
	bg := node.mongo.GetBlockFromDatabase(res.height)

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
	pageSize int
	pageNum  int
}

// GetBlockInfByPage 按页获取区块的所有信息
//
// @Description: 按页获取区块的所有信息
// @receiver node
// @param res
// @param conn
//
func (node *Node) getBlockInfByPage(c *gin.Context) {
	res := BlockInfRequest{}

	err := c.BindJSON(&res)
	if err != nil {
		common.Logger.Error("解析crs request失败", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
	}
	//if res["PageSize"] == nil || res["PageNum"] == nil {
	//	resp := CommonResponse{Code: code.LESS_PARAMETER, Message: "缺少字段", Data: nil}
	//	data, err := json.Marshal(resp)
	//	if err != nil {
	//		common.Logger.Error(err)
	//	}
	//	Network.SendResponse(conn, data, res["Key"].(string))
	//	return
	//}
	pageSize := res.pageSize
	pageNum := res.pageNum
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

	var message PageBlockGroupInf

	message.blockgroups = bgs
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
