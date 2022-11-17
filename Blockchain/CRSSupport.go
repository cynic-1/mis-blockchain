package Node

import (
	"MIS-BC/MetaData"
	"MIS-BC/common"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"runtime/debug"
	"sync"
)

// User 结构体定义
type UploadReq struct {
	Name  string `json:"name" form:"name"`
	Email string `json:"email" form:"email"`
}

type crsPool struct {
	crsChan chan interface{}
	crsPool sync.Pool
}

func (node *Node) HandleCRSMessage(v *gin.RouterGroup) {
	// ping 测试路由
	v.GET("/ping", node.ping)
	// 存储crs上传至MIS的记录的路由
	v.POST("/upload", node.upload)
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
	// node.mongo.UpdateIdentityModifyRecordsforUploadUserLog(log)
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
