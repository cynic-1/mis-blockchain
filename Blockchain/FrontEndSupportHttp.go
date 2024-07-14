package Node

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetupHTTPServer 设置 HTTP 服务器和路由
func (node *Node) SetupHTTPServer() *gin.Engine {
	router := gin.Default()

	v1 := router.Group("/misApi/api/v1/mis")
	{
		v1.GET("/getOverviewInfo", node.getOverviewInfoHttp)
		v1.GET("/getBlockInfByPage", node.GetBlockInfByPageHttp)
		v1.GET("/getTransactionInfByPage", node.getTransactionInfByPage)
		v1.GET("/getTransactionAnalysis", node.getTransactionAnalysis)
		v1.GET("/getLastBGsInfo", node.getLastBGsInfo)
		v1.GET("/getLastTransactionsInfo", node.getLastTransactionsInfo)
		v1.GET("/getBGMsgOfCertainHeightFromServer", node.getBGMsgOfCertainHeightFromServer)
		v1.GET("/getTransactionInfByTxtNum", node.getTransactionInfByTxtNum)
	}

	return router
}

func (node *Node) getOverviewInfoHttp(c *gin.Context) {
	node.BCStatus.Mutex.RLock()
	info := BCOverviewInfo{
		Height:   node.BCStatus.Overview.Height,
		Total:    node.BCStatus.Overview.TransactionNum,
		Handling: node.BCStatus.Overview.ProcessingTransactionNum,
		NodeNum:  node.BCStatus.Overview.NodeNum,
	}
	node.BCStatus.Mutex.RUnlock()

	response := CommonResponse{
		Code:    code.SUCCESS,
		Message: "获取区块链状态概要信息成功",
		Data:    info,
	}

	c.JSON(http.StatusOK, response)
}

func (node *Node) GetBlockInfByPageHttp(c *gin.Context) {
	// 获取查询参数
	pageSizeStr := c.Query("PageSize")
	pageNumStr := c.Query("PageNum")

	if pageSizeStr == "" || pageNumStr == "" {
		c.JSON(http.StatusBadRequest, CommonResponse{
			Code:    code.LESS_PARAMETER,
			Message: "缺少字段",
			Data:    nil,
		})
		return
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, CommonResponse{
			Code:    code.INVALID_PARAMETER,
			Message: "PageSize 参数无效",
			Data:    nil,
		})
		return
	}

	pageNum, err := strconv.Atoi(pageNumStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, CommonResponse{
			Code:    code.INVALID_PARAMETER,
			Message: "PageNum 参数无效",
			Data:    nil,
		})
		return
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

	message := PageBlockGroupInf{
		Blockgroups: bgs,
		Total:       len(bgs),
	}

	c.JSON(http.StatusOK, CommonResponse{
		Code:    code.SUCCESS,
		Message: "获取分页区块组信息成功",
		Data:    message,
	})
}

// 原来就没实现
func getTransactionInfByPage(c *gin.Context) {
	// TODO: Implement business logic
	c.JSON(http.StatusOK, gin.H{"message": "Transaction info by page"})
}

func (node *Node) getTransactionAnalysisHttp(c *gin.Context) {
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

	c.JSON(http.StatusOK, CommonResponse{
		Code:    code.SUCCESS,
		Message: "获取区块链近15天交易量成功",
		Data:    txsnum,
	})
}

func (node *Node) getLastBGsInfoHttp(c *gin.Context) {
	var bgs []interface{}
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.BgsList.Front(); i != nil; i = i.Next() {
		bgs = append(bgs, i.Value)
	}
	node.BCStatus.Mutex.RUnlock()

	c.JSON(http.StatusOK, CommonResponse{
		Code:    code.SUCCESS,
		Message: "获取最近10个区块组成功",
		Data:    bgs,
	})
}

func (node *Node) getLastTransactionsInfoHttp(c *gin.Context) {
	var txs []interface{}
	node.BCStatus.Mutex.RLock()
	for i := node.BCStatus.TxsList.Front(); i != nil; i = i.Next() {
		txs = append(txs, i.Value)
	}
	node.BCStatus.Mutex.RUnlock()

	c.JSON(http.StatusOK, CommonResponse{
		Code:    code.SUCCESS,
		Message: "获取最近10个交易成功",
		Data:    bgs,
	})
}

func (node *Node) GetBGMsgOfCertainHeight(c *gin.Context) {
	// 从URL参数中获取Height
	heightStr := c.Query("Height")
	if heightStr == "" {
		c.JSON(http.StatusBadRequest, CommonResponse{
			Code:    code.LESS_PARAMETER,
			Message: "缺少Height参数",
			Data:    nil,
		})
		return
	}

	height, err := strconv.Atoi(heightStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, CommonResponse{
			Code:    code.INVALID_PARAMETER,
			Message: "Height参数无效",
			Data:    nil,
		})
		return
	}

	common.Logger.Info("MISGetBlockGroup", height)
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

	c.JSON(http.StatusOK, CommonResponse{
		Code:    code.SUCCESS,
		Message: "获取该高度的区块组成功",
		Data:    bg,
	})
}

// 原来就没实现
func getTransactionInfByTxtNum(c *gin.Context) {
	// TODO: Implement business logic
	c.JSON(http.StatusOK, gin.H{"message": "Transaction info by text number"})
}
