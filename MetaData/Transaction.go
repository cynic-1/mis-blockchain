package MetaData

const (
	Zero               = 0
	Genesis            = 1
	IdTransformation   = 2
	IdentityAction     = 3
	ElectNewWorker     = 4
	UserLogOperation   = 5
	CRSRecordOperation = 6
)

type TransactionInterface interface {
	ToByteArray() []byte
	FromByteArray(data []byte)
}

//go:generate msgp
type TransactionHeader struct {
	TXType int    `msg:"tx"`
	Data   []byte `msg:"data"`
}

func EncodeTransaction(header TransactionHeader, transactionInterface TransactionInterface) (data []byte) {
	data = transactionInterface.ToByteArray()
	header.Data = data
	data, _ = header.MarshalMsg(nil)
	return data
}

func DecodeTransaction(data []byte) (header TransactionHeader, transactionInterface TransactionInterface) {
	data, _ = header.UnmarshalMsg(data)
	data = header.Data
	switch header.TXType {
	case Zero:
		var zt ZeroTransaction
		zt.FromByteArray(data)
		transactionInterface = &zt
	case Genesis:
		var gt GenesisTransaction
		gt.FromByteArray(data)
		transactionInterface = &gt
	case IdTransformation:
		var idt IdentityTransformation
		idt.FromByteArray(data)
		transactionInterface = &idt
	case IdentityAction:
		var id Identity
		id.FromByteArray(data)
		transactionInterface = &id
	case UserLogOperation:
		var ul UserLog
		ul.FromByteArray(data)
		transactionInterface = &ul
	case CRSRecordOperation:
		var cr CrsChainRecord
		cr.FromByteArray(data)
		transactionInterface = &cr
	case ElectNewWorker:
		var emwt ElectNewWorkerTeam
		emwt.FromByteArray(data)
		transactionInterface = &emwt
	}
	return
}
