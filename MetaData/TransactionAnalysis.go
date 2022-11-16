package MetaData

import (
	"errors"
	"fmt"
)

type TransactionAnalysis struct {
	TxsNum    uint64   `json:"txsnum"`
	PreTxsNum uint64   `json:"pretxsnum"`
	TxsList   []uint64 `json:"txslist"`
}

func (ta TransactionAnalysis) ToByteArray() []byte {
	data, _ := ta.MarshalMsg(nil)
	return data
}

func (ta *TransactionAnalysis) FromByteArray(data []byte) {
	_, err := ta.UnmarshalMsg(data)
	if err != nil {
		fmt.Println("err=", err)
	}
}

func mat(asd string) error {
	return errors.New("123")
}
