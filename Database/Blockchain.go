/**
 * @Author: xzw
 * @Description:
 * @Version: 1.0.0
 * @Date: 2021/6/15 下午4:00
 * @Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
 */

package MongoDB

import (
	"MIS-BC/MetaData"
	"MIS-BC/common"
	"MIS-BC/utils"
	"encoding/json"
	"gopkg.in/mgo.v2/bson"
	"hash/crc32"
	"log"
	"strconv"
)

func (pl *Mongo) QueryHeight() int {
	var height = -1
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "blockstate"
	session := pl.pool.AcquireSession()
	//session.SetMode(mgo.Monotonic, true)
	defer session.Release()

	var item MetaData.BlockState
	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if err != nil {
		log.Println(err)
	}
	if count > 0 {
		c := session.DB("blockchain").C(subname)
		err := c.Find(nil).One(&item)
		if err != nil {
			log.Println(err)
		}
		height = item.Height
	}

	return height
}

func (pl *Mongo) SetHeight(height int) {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "blockstate"
	session := pl.pool.AcquireSession()
	//session.SetMode(mgo.Monotonic, true)
	defer session.Release()

	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if err != nil {
		log.Println(err)
	}

	if count > 0 {
		item := make(map[string]interface{})
		c := session.DB("blockchain").C(subname)
		err := c.Find(nil).One(item)
		if err != nil {
			log.Println(err)
		}
		selector := bson.M{"_id": item["_id"]}
		data := bson.M{"$set": bson.M{"height": height}}

		err = c.Update(selector, data)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		blockstate := MetaData.BlockState{Height: height}
		pl.saveBlockstateToDatabase(blockstate)
	}
}

func (pl *Mongo) saveBlockstateToDatabase(item MetaData.BlockState) {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "blockstate"
	pl.InsertToMogoBlockstate(item, subname)
}

func (pl *Mongo) SaveBCStatusToDatabase(item MetaData.BCStatus) {
	typ := "bcstatus"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ

	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	if count > pl.CacheNumber {
		var bs MetaData.BCStatus
		c.Find(nil).Sort("timestamp").Limit(1).One(&bs)
		c.RemoveAll(bson.M{"timestamp": bs.Timestamp})
	}
	pl.InsertToMogoBCStatus(item, subname)
}

func (pl *Mongo) GetBCStatusFromDatabase() MetaData.BCStatus {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "bcstatus"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var item MetaData.BCStatus
	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if count > pl.CacheNumber {
		var bs MetaData.BCStatus
		c.Find(nil).Sort("timestamp").Limit(1).One(&bs)
		c.RemoveAll(bson.M{"timestamp": bs.Timestamp})
		err = c.Find(nil).Sort("-timestamp").Skip(pl.CacheNumber * 9 / 10).Limit(1).One(&item)
		if err != nil {
			common.Logger.Error(err)
		}
	} else {
		err = c.Find(nil).Sort("timestamp").Limit(1).One(&item)
		if err != nil {
			common.Logger.Error(err)
		}
		_, err = c.RemoveAll(bson.M{"timestamp": item.Timestamp})
		if err != nil {
			common.Logger.Error(err)
		}
	}

	return item
}

func (pl *Mongo) DeleteBCStatus(key, value string) {
	typ := "bcstatus"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ
	session := pl.pool.AcquireSession()
	defer session.Release()
	c := session.DB("blockchain").C(subname)
	_, err := c.RemoveAll(bson.M{key: value})
	if err != nil {
		log.Println(err)
	}
}

func (pl *Mongo) HasTransactionAnalysis() bool {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "txs_analysis"
	session := pl.pool.AcquireSession()
	//session.SetMode(mgo.Monotonic, true)
	defer session.Release()

	c := session.DB("blockchain").C(subname)
	nums, err := c.Find(nil).Count()
	if err != nil {
		log.Println(err)
	}
	if nums > 0 {
		return true
	}
	return false
}

func (pl *Mongo) SaveTransactionAnalysisToDatabase(item MetaData.TransactionAnalysis) {
	typ := "txs_analysis"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ

	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	if count > 0 {
		var ta MetaData.TransactionAnalysis
		c.Find(nil).One(&ta)
		c.Remove(ta)
	}
	pl.InsertToMogoTransactionAnalysis(item, subname)
}

func (pl *Mongo) GetTransactionAnalysisFromDatabase() MetaData.TransactionAnalysis {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "txs_analysis"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var item MetaData.TransactionAnalysis
	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if count == 1 {
		err = c.Find(nil).Limit(1).One(&item)
		if err != nil {
			common.Logger.Error(err)
		}
	}

	return item
}

func (pl *Mongo) HasTransactionList() bool {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "txs_list"
	session := pl.pool.AcquireSession()
	//session.SetMode(mgo.Monotonic, true)
	defer session.Release()

	c := session.DB("blockchain").C(subname)
	nums, err := c.Find(nil).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	if nums > 0 {
		return true
	}
	return false
}

func (pl *Mongo) SaveTransactionListToDatabase(item []MetaData.CrsChainRecord) {
	typ := "txs_list"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ

	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	if count > 0 {
		var ta []MetaData.CrsChainRecord
		c.Find(nil).One(&ta)
		c.Remove(ta)
	}
	pl.InsertToMogoTransactionList(item, subname)
}

func (pl *Mongo) GetTransactionListFromDatabase() []MetaData.CrsChainRecord {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "txs_list"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var item []MetaData.CrsChainRecord
	c := session.DB("blockchain").C(subname)
	count, err := c.Find(nil).Count()
	if count == 1 {
		err = c.Find(nil).Limit(1).One(&item)
		if err != nil {
			common.Logger.Error(err)
		}
	}

	return item
}

func (pl *Mongo) GetAmount() int {
	return pl.QueryHeight() + 1
}

func (pl *Mongo) PushbackBlockToDatabase(block MetaData.BlockGroup) {
	if block.Height == 0 {
		block.CheckHeader = []int{1}
	}
	pl.InsertToMogoBG(block, pl.Pubkey)
	pl.Block = block
	pl.Height = block.Height
	pl.SetHeight(block.Height)
}

func (pl *Mongo) GetBlockFromDatabase(height int) MetaData.BlockGroup {
	session := pl.pool.AcquireSession()
	//session.SetMode(mgo.Monotonic, true)
	defer session.Release()

	var blockgroup MetaData.BlockGroup
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	c := session.DB("blockchain").C(index + "-blockgroup" + "-" + strconv.Itoa(height/(10*10000)))
	err := c.Find(bson.M{"height": height}).One(&blockgroup)
	if err != nil {
		log.Println(err)
	}

	var blocks []MetaData.Block
	c1 := session.DB("blockchain").C(index + "-block" + "-" + strconv.Itoa(height/(10*10000)))
	err = c1.Find(bson.M{"height": height}).All(&blocks)
	if err != nil {
		log.Println(err)
	}

	true_blocks := make([]MetaData.Block, len(blockgroup.CheckHeader))
	for _, v := range blocks {
		true_blocks[v.BlockNum] = v
	}

	blockgroup.Blocks = true_blocks
	return blockgroup
}

func (pl *Mongo) GetLastBGsInfo() []MetaData.BlockGroup {
	bgs := make([]MetaData.BlockGroup, 10)
	for i := 0; i < 10; i++ {
		if pl.Height-i < 0 {
			break
		}
		bgs[i] = pl.GetBlockFromDatabase(pl.Height - 9 + i)

		if bgs[i].Height > 0 {
			for x, eachBlock := range bgs[i].Blocks {
				for _, eachTransaction := range eachBlock.Transactions {
					transactionHeader, transactionInterface := MetaData.DecodeTransaction(eachTransaction)
					switch transactionHeader.TXType {
					case MetaData.IdentityAction:
						if transaction, ok := transactionInterface.(*MetaData.Identity); ok {
							data, _ := json.Marshal(transaction)
							bgs[i].Blocks[x].Transactions_s = append(bgs[i].Blocks[x].Transactions_s, string(data))
						}
					case MetaData.IdTransformation:
						if transaction, ok := transactionInterface.(*MetaData.IdentityTransformation); ok {
							data, _ := json.Marshal(transaction)
							bgs[i].Blocks[x].Transactions_s = append(bgs[i].Blocks[x].Transactions_s, string(data))
						}
					case MetaData.UserLogOperation:
						if transaction, ok := transactionInterface.(*MetaData.UserLog); ok {
							data, _ := json.Marshal(transaction)
							bgs[i].Blocks[x].Transactions_s = append(bgs[i].Blocks[x].Transactions_s, string(data))
						}
					case MetaData.CRSRecordOperation:
						if transaction, ok := transactionInterface.(*MetaData.CrsChainRecord); ok {
							data, _ := json.Marshal(transaction)
							bgs[i].Blocks[x].Transactions_s = append(bgs[i].Blocks[x].Transactions_s, string(data))
						}
					}

				}
			}
		} else if bgs[i].Height == 0 {
			if len(bgs[i].Blocks) != 0 {
				if bgs[i].Blocks[0].Height == 0 {
					transactionHeader, transactionInterface := MetaData.DecodeTransaction(bgs[i].Blocks[0].Transactions[0])
					if transactionHeader.TXType == MetaData.Genesis {
						if genesisTransaction, ok := transactionInterface.(*MetaData.GenesisTransaction); ok {
							data, _ := json.Marshal(genesisTransaction)
							bgs[i].Blocks[0].Transactions_s = append(bgs[i].Blocks[0].Transactions_s, string(data))
						}
					}
				}
			}
		}
	}
	return bgs
}

func (pl *Mongo) GetPageBlockFromDatabase(skip, limit int) []MetaData.BlockGroup {
	session := pl.pool.AcquireSession()
	//session.SetMode(mgo.Monotonic, true)
	defer session.Release()

	blockgroup := make([]MetaData.BlockGroup, limit)
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))

	first := (skip + 1) % 100000
	last := (skip + limit) % 100000

	c1 := session.DB("blockchain").C(index + "-blockgroup" + "-" + strconv.Itoa((skip+1)/(10*10000)))

	if 99990 <= first && first < 100000 && 0 <= last && last < 10 {
		err := c1.Find(nil).Sort("-height").Skip(skip).Limit(limit).All(&blockgroup)
		if err != nil {
			common.Logger.Error(err)
		}

		blockgroup1 := make([]MetaData.BlockGroup, limit-len(blockgroup))

		c2 := session.DB("blockchain").C(index + "-blockgroup" + "-" + strconv.Itoa((skip+1)/(10*10000)+1))
		err = c2.Find(nil).Sort("-height").Skip(skip).Limit(limit).All(&blockgroup1)
		if err != nil {
			common.Logger.Error(err)
		}

		c3 := session.DB("blockchain").C(index + "-block" + "-" + strconv.Itoa((skip+1)/(10*10000)))
		for _, bg := range blockgroup {
			var blocks []MetaData.Block
			err = c3.Find(bson.M{"height": bg.Height}).All(&blocks)
			if err != nil {
				common.Logger.Error(err)
			}

			true_blocks := make([]MetaData.Block, len(bg.CheckHeader))
			for _, v := range blocks {
				true_blocks[v.BlockNum] = v
			}
			bg.Blocks = true_blocks
		}

		c4 := session.DB("blockchain").C(index + "-block" + "-" + strconv.Itoa((skip+1)/(10*10000)+1))
		for _, bg := range blockgroup1 {
			var blocks []MetaData.Block
			err = c4.Find(bson.M{"height": bg.Height}).All(&blocks)
			if err != nil {
				common.Logger.Error(err)
			}

			true_blocks := make([]MetaData.Block, len(bg.CheckHeader))
			for _, v := range blocks {
				true_blocks[v.BlockNum] = v
			}
			bg.Blocks = true_blocks
			blockgroup = append(blockgroup, bg)
		}

	} else {
		err := c1.Find(nil).Sort("-height").Skip(skip).Limit(limit).All(&blockgroup)
		if err != nil {
			common.Logger.Error(err)
		}

		for _, bg := range blockgroup {
			var blocks []MetaData.Block
			c3 := session.DB("blockchain").C(index + "-block" + "-" + strconv.Itoa(bg.Height/(10*10000)))
			err = c3.Find(bson.M{"height": bg.Height}).All(&blocks)
			if err != nil {
				common.Logger.Error(err)
			}

			true_blocks := make([]MetaData.Block, len(bg.CheckHeader))
			for _, v := range blocks {
				true_blocks[v.BlockNum] = v
			}
			bg.Blocks = true_blocks
		}
	}

	return blockgroup
}

func (pl *Mongo) GetPageBlockFromDatabaseByTimestamp(skip, limit int, beginTime, endTime float64) []MetaData.BlockGroup {
	session := pl.pool.AcquireSession()
	//session.SetMode(mgo.Monotonic, true)
	defer session.Release()

	blockgroup := make([]MetaData.BlockGroup, limit)
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))

	first := (skip + 1) % 100000
	last := (skip + limit) % 100000

	c1 := session.DB("blockchain").C(index + "-blockgroup" + "-" + strconv.Itoa((skip+1)/(10*10000)))

	if 99990 <= first && first < 100000 && 0 <= last && last < 10 {
		err := c1.Find(bson.M{"timestamp": bson.M{"$lte": endTime, "$gte": beginTime}}).Sort("-height").Skip(skip).Limit(limit).All(&blockgroup)
		if err != nil {
			common.Logger.Error(err)
		}

		blockgroup1 := make([]MetaData.BlockGroup, limit-len(blockgroup))

		c2 := session.DB("blockchain").C(index + "-blockgroup" + "-" + strconv.Itoa((skip+1)/(10*10000)+1))
		err = c2.Find(bson.M{"timestamp": bson.M{"$lte": endTime, "$gte": beginTime}}).Sort("-height").Skip(skip).Limit(limit).All(&blockgroup1)
		if err != nil {
			common.Logger.Error(err)
		}

		c3 := session.DB("blockchain").C(index + "-block" + "-" + strconv.Itoa((skip+1)/(10*10000)))
		for _, bg := range blockgroup {
			var blocks []MetaData.Block
			err = c3.Find(bson.M{"height": bg.Height}).All(&blocks)
			if err != nil {
				common.Logger.Error(err)
			}

			true_blocks := make([]MetaData.Block, len(bg.CheckHeader))
			for _, v := range blocks {
				true_blocks[v.BlockNum] = v
			}
			bg.Blocks = true_blocks
		}

		c4 := session.DB("blockchain").C(index + "-block" + "-" + strconv.Itoa((skip+1)/(10*10000)+1))
		for _, bg := range blockgroup1 {
			var blocks []MetaData.Block
			err = c4.Find(bson.M{"height": bg.Height}).All(&blocks)
			if err != nil {
				common.Logger.Error(err)
			}

			true_blocks := make([]MetaData.Block, len(bg.CheckHeader))
			for _, v := range blocks {
				true_blocks[v.BlockNum] = v
			}
			bg.Blocks = true_blocks
			blockgroup = append(blockgroup, bg)
		}

	} else {
		err := c1.Find(bson.M{"timestamp": bson.M{"$lte": endTime, "$gte": beginTime}}).Sort("-height").Skip(skip).Limit(limit).All(&blockgroup)
		if err != nil {
			common.Logger.Error(err)
		}

		for _, bg := range blockgroup {
			var blocks []MetaData.Block
			c3 := session.DB("blockchain").C(index + "-block" + "-" + strconv.Itoa(bg.Height/(10*10000)))
			err = c3.Find(bson.M{"height": bg.Height}).All(&blocks)
			if err != nil {
				common.Logger.Error(err)
			}

			true_blocks := make([]MetaData.Block, len(bg.CheckHeader))
			for _, v := range blocks {
				true_blocks[v.BlockNum] = v
			}
			bg.Blocks = true_blocks
		}
	}

	return blockgroup
}

type Transaction struct {
	TXType    int    `msg:"txtype"`
	TXTNum    string `msg:"txtnum"`
	Timestamp string `msg:"timestamp"`
	Data      string `msg:"data"`
}

func (pl *Mongo) SaveTransactionToDatabase(txtype int, transaction string) {
	var trans Transaction
	typ := "Transaction"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ
	trans.TXType = txtype
	trans.Data = transaction
	trans.Timestamp = strconv.FormatFloat(utils.GetCurrentTime(), 'f', 0, 64)
	trans.TXTNum = utils.GetMD5Encode(trans.Timestamp + trans.Data)
	pl.InsertToMogoTransaction(trans, subname)
}

func (pl *Mongo) GetPageTransFromDatabase(skip, limit int) []Transaction {
	typ := "Transaction"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ
	session := pl.pool.AcquireSession()
	defer session.Release()

	transactions := make([]Transaction, limit)
	c := session.DB("blockchain").C(subname)
	err := c.Find(nil).Skip(skip).Limit(limit).All(&transactions)
	if err != nil {
		common.Logger.Error(err)
	}
	return transactions
}

func (pl *Mongo) GetPageTransFromDatabaseByTimestamp(skip, limit int, beginTime, endTime string) []Transaction {
	typ := "Transaction"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ
	session := pl.pool.AcquireSession()
	defer session.Release()

	transactions := make([]Transaction, limit)
	c := session.DB("blockchain").C(subname)
	err := c.Find(bson.M{"timestamp": bson.M{"$lte": endTime, "$gte": beginTime}}).Skip(skip).Limit(limit).All(&transactions)
	if err != nil {
		common.Logger.Error(err)
	}
	return transactions
}

func (pl *Mongo) GetPageTransFromDatabaseByTxtNum(txtNum string) Transaction {
	typ := "Transaction"
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + typ
	session := pl.pool.AcquireSession()
	defer session.Release()

	var transaction Transaction
	c := session.DB("blockchain").C(subname)
	err := c.Find(bson.M{"txtnum": txtNum}).One(&transaction)
	if err != nil {
		common.Logger.Error(err)
	}
	return transaction
}
