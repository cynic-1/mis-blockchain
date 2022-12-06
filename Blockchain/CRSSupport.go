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

	////add post body
	//var bodyJson []byte
	//var req *http.Request
	//if body != nil {
	//	var err error
	//	bodyJson, err = json.Marshal(body)
	//	if err != nil {
	//		log.Println(err)
	//		return nil, errors.New("http post body to json failed")
	//	}
	//}
	//req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyJson))
	//if err != nil {
	//	log.Println(err)
	//	return nil, errors.New("new request is fail: %v \n")
	//}
	//req.Header.Set("Content-type", "application/json")
	////add params
	//q := req.URL.Query()
	//if params != nil {
	//	for key, val := range params {
	//		q.Add(key, val)
	//	}
	//	req.URL.RawQuery = q.Encode()
	//}
	////add headers
	//if headers != nil {
	//	for key, val := range headers {
	//		req.Header.Add(key, val)
	//	}
	//}
	////http client
	//client := &http.Client{}
	//log.Printf("Go %s URL : %s \n", http.MethodPost, req.URL.String())
	//return client.Do(req)
}
