package MetaData

import "fmt"

//go:generate msgp
type CrsChainRecord struct {
	EntId           int    `msg:"entId"`
	BlockHash       string `msg:"blockHash"`
	TransactionHash string `msg:"transactionHash"`
	Data            string `msg:"data"`
	CreateTime      string `msg:"createTime"`
	BelongTo        int    `msg:"belongTo"`
}

func (c CrsChainRecord) ToByteArray() []byte {
	data, _ := c.MarshalMsg(nil)
	return data
}

func (c *CrsChainRecord) FromByteArray(data []byte) {
	_, err := c.UnmarshalMsg(data)
	if err != nil {
		fmt.Println("err=", err)
	}
}
