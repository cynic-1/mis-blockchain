package MongoDB

import (
	"MIS-BC/MetaData"
	"MIS-BC/utils"
	"hash/crc32"
	"strconv"
)

func (pl *Mongo) SaveCRSRecordToDatabase(item MetaData.CrsChainRecord) {
	typ := "CRS_Record"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ

	pl.InsertToMogoCRSRecord(encryptRecord(item), subname)
}

func decryptAllRecord(sources []MetaData.CrsChainRecord) []MetaData.CrsChainRecord {
	var results []MetaData.CrsChainRecord

	for _, records := range sources {
		results = append(results, decryptRecord(records))
	}

	return results
}

func decryptRecord(source MetaData.CrsChainRecord) MetaData.CrsChainRecord {
	result := MetaData.CrsChainRecord{}

	result.TransactionHash = checkRecordforDecrypt(source.TransactionHash)
	result.BlockHash = checkRecordforDecrypt(source.BlockHash)
	result.CreateTime = checkRecordforDecrypt(source.CreateTime)
	result.Data = checkRecordforDecrypt(source.Data)
	result.BelongTo = source.BelongTo
	result.EntId = source.EntId

	return result
}

func encryptRecord(source MetaData.CrsChainRecord) MetaData.CrsChainRecord {
	result := MetaData.CrsChainRecord{}

	result.TransactionHash = checkRecordforEncrypt(source.TransactionHash)
	result.BlockHash = checkRecordforEncrypt(source.BlockHash)
	result.CreateTime = checkRecordforEncrypt(source.CreateTime)
	result.Data = checkRecordforEncrypt(source.Data)
	result.BelongTo = source.BelongTo
	result.EntId = source.EntId

	return result
}

func checkRecordforEncrypt(source string) string {
	var result string
	if source == "" {
		result = ""
	} else {
		result = utils.EncryptString(source)
	}
	return result
}

func checkRecordforDecrypt(source string) string {
	var result string
	if source == "" {
		result = ""
	} else {
		result = utils.DecryptString(source)
	}
	return result
}
