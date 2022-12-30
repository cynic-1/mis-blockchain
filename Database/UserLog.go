/**
 * @Author: xzw
 * @Description:
 * @Version: 1.0.0
 * @Date: 2021/6/21 早上9:00
 * @Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
 */

package MongoDB

import (
	"MIS-BC/MetaData"
	"MIS-BC/common"
	"MIS-BC/utils"
	"fmt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"hash/crc32"
	"log"
	"strconv"
	"time"
)

func (pl *Mongo) SaveNormalUserLogToDatabase(item MetaData.UserLog) {
	typ1 := "UserLog"
	typ2 := "UserLog-All"

	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname1 := index + "-" + typ1
	subname2 := index + "-" + typ2

	pl.InsertToMogoUserLog(encryptUserLog(item), subname1)
	pl.InsertToMogoUserLog(encryptUserLog(item), subname2)

}

func (pl *Mongo) SaveWarningUserLogToDatabase(item MetaData.UserLog) {
	typ1 := "UserLog-Warning"
	typ2 := "UserLog-All"

	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname1 := index + "-" + typ1
	subname2 := index + "-" + typ2

	pl.InsertToMogoUserLog(encryptUserLog(item), subname1)
	pl.InsertToMogoUserLog(encryptUserLog(item), subname2)
}

func (pl *Mongo) GetLogsByIdentityIdentifierFromDatabase(identityidentifier string) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": bson.M{"$regex": bson.RegEx{Pattern: utils.EncryptString(identityidentifier), Options: "i"}}}).All(&items)
	if err != nil {
		log.Println(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetLogsByRangeTimeFromDatabase(start, end string) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).All(&items)
	if err != nil {
		log.Println(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageLogsByIdentityIdentifierFromDatabase(identityidentifier string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier)}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageLogsCountByIdentityIdentifierFromDatabase(identityidentifier string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier)}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageLogsByRangeTimeFromDatabase(start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"name": "Jimmy Kuu", "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		log.Println(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageLogsCountByRangeTimeFromDatabase(start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		log.Println(err)
	}
	return total
}

func (pl *Mongo) GetNormalLogsByTimestampFromDatabase(start, end string) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetNormalLogsCountByTimestampFromDatabase(start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageNormalLogsByTimestampFromDatabase(start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageNormalLogsCountByTimestampFromDatabase(start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetAllWarningLogsByTimestampFromDatabase(start, end string) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetAllWarningLogsCountByTimestampFromDatabase(start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageWarningLogsByTimestampFromDatabase(start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageWarningLogsCountByTimestampFromDatabase(start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageLogsByTimestampFromDatabase(start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-All"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageLogsCountByTimestampFromDatabase(start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-All"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetAllNormalLogsByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetAllNormalLogsCountByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetAllNormalLogsCountByGroupIDFromDatabase(ugroupid int) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"ugroupid": ugroupid}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageNormalLogsByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageNormalLogsCountByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetAllWarningLogsByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetAllWarningLogsCountByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetAllWarningLogsCountByGroupIDFromDatabase(ugroupid int) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"ugroupid": ugroupid}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageWarningLogsByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageWarningLogsCountByGroupIDAndTimestampFromDatabase(ugroupid int, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"ugroupid": ugroupid, "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageNormalLogsByUserNameAndTimestampFromDatabase(name, start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"name": utils.EncryptString(name), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageNormalLogsCountByUserNameAndTimestampFromDatabase(name, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"name": utils.EncryptString(name), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageWarningLogsByUserNameAndTimestampFromDatabase(name, start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"name": utils.EncryptString(name), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageWarningLogsCountByUserNameAndTimestampFromDatabase(name, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"name": utils.EncryptString(name), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageNormalLogsByIdentityFromDatabase(identityidentifier string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier)}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageNormalLogsCountByIdentityFromDatabase(identityidentifier string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier)}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageWarningLogsByIdentityFromDatabase(identityidentifier string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier)}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageWarningLogsCountByIdentityFromDatabase(identityidentifier string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier)}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageNormalLogsByIdentityAndTimestampFromDatabase(identityidentifier, start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageNormalLogsCountByIdentityAndTimestampFromDatabase(identityidentifier, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageWarningLogsByIdentityAndTimestampFromDatabase(identityidentifier, start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageNormalLogsByTimestampAndIdentifierFromDatabase(start, end, id string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(id), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageNormalLogsCountByTimestampAndIdentifierFromDatabase(start, end, id string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(id), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageWarningLogsByTimestampAndIdentifierFromDatabase(start, end, id string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(id), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageWarningLogsCountByTimestampAndIdentifierFromDatabase(start, end, id string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(id), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageWarningLogsCountByIdentityAndTimestampFromDatabase(identityidentifier, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetPageLogsByTimestampAndIdentifierFromDatabase(start, end, id string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-All"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(id), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		common.Logger.Error(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageLogsCountByTimestampAndIdentifierFromDatabase(start, end, id string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-All"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(id), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	return total
}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseByYear() []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	endtime := time.Now()
	starttime := endtime.AddDate(-1, 0, 0)
	//endtime, err := strconv.ParseInt(end, 10, 64)
	//if err != nil {
	//	common.Logger.Error(err)
	//}

	//t, err := strconv.ParseInt(newstart, 10, 64)
	//if err != nil {
	//	common.Logger.Error(err)
	//}
	// newstart := strconv.FormatInt(endtime.Unix(),10)
	var newstart, newend int64
	for i := 0; i < 12; i++ {
		newstart = starttime.AddDate(0, i, 0).Unix()
		newend = starttime.AddDate(0, i+1, 0).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}
	//m1 := bson.M{"$match": bson.M{"username": username}}
	//m2 := bson.M{"$group": bson.M{"_id": "$action", "count": bson.M{"$sum": 1}}}
	//m3 := bson.M{"$skip": skip}
	//m4 := bson.M{"$limit": limit}
	//m5 := bson.M{"$project": bson.M{"action": "$_id", "count": 1}}
	//m6 := bson.M{"$sort": bson.M{"count": -1}}
	//err := c.Pipe([]bson.M{m1, m2, m3, m4, m5, m6}).All(&items)
	//if err != nil {
	//	log.Println(err)
	//}

	if len(items) != 12 {
		common.Logger.Error("incorrect number of days")
		return nil
	} else {
		return items
	}
}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseByYear() []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	endtime := time.Now()
	starttime := endtime.AddDate(-1, 0, 0)

	var newstart, newend int64
	for i := 0; i < 12; i++ {
		newstart = starttime.AddDate(0, i, 0).Unix()
		newend = starttime.AddDate(0, i+1, 0).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}

	if len(items) != 12 {
		common.Logger.Error("incorrect number of months")
		return nil
	} else {
		return items
	}
}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseByMonth() []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	endtime := time.Now()
	starttime := endtime.AddDate(0, -1, 0)
	dur := int(endtime.Sub(starttime).Hours() / 24)
	//endtime, err := strconv.ParseInt(end, 10, 64)

	var newstart, newend int64
	for i := 0; i < dur; i++ {
		newstart = starttime.AddDate(0, 0, i).Unix()
		newend = starttime.AddDate(0, 0, i+1).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}

	if len(items) != dur {
		common.Logger.Error("incorrect number of days")
		return nil
	} else {
		return items
	}
}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseByMonth() []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	endtime := time.Now()
	starttime := endtime.AddDate(0, -1, 0)
	dur := int(endtime.Sub(starttime).Hours() / 24)

	var newstart, newend int64
	for i := 0; i < dur; i++ {
		newstart = starttime.AddDate(0, 0, i).Unix()
		newend = starttime.AddDate(0, 0, i+1).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}

	if len(items) != dur {
		common.Logger.Error("incorrect number of days")
		return nil
	} else {
		return items
	}
}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end string, l int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	tmp1, _ := strconv.ParseInt(start, 10, 64)
	tmp2, _ := strconv.ParseInt(end, 10, 64)
	starttime := time.Unix(tmp1, 0).Local()
	endtime := time.Unix(tmp2, 0).Local()
	//starttime := endtime.AddDate(-1, 0, 0)
	month := int(endtime.Month())
	// days := endtime.Day()

	// common.Logger.Info("month:", month, "days:", days)

	var newstart, newend int64
	for i := 0; i < month-1; i++ { //今年第一个月到现在的前一个月的日志数量
		newstart = starttime.AddDate(0, i, 0).Unix()
		newend = starttime.AddDate(0, i+1, 0).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}
	//从月初到now的日志数量
	// thismonth := endtime.AddDate(0, 0, -days).Unix()
	thismonthnum, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(endtime.Unix(), 10), "$gte": strconv.FormatInt(newend, 10)}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	items = append(items, thismonthnum)

	if len(items) != l {
		common.Logger.Error("incorrect number of months")
		return nil
	} else {
		return items
	}
}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end string, l int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"

	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	tmp1, _ := strconv.ParseInt(start, 10, 64)
	tmp2, _ := strconv.ParseInt(end, 10, 64)
	starttime := time.Unix(tmp1, 0).Local()
	endtime := time.Unix(tmp2, 0).Local()
	//starttime := endtime.AddDate(-1, 0, 0)
	month := int(endtime.Month())
	// days := endtime.Day()
	var newstart, newend int64
	for i := 0; i < month-1; i++ { //今年第一个月到现在的前一个月的日志数量
		newstart = starttime.AddDate(0, i, 0).Unix()
		newend = starttime.AddDate(0, i+1, 0).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}
	//从月初到now的日志数量
	// thismonth := endtime.AddDate(0, 0, -days+1).Unix()
	thismonthnum, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(endtime.Unix(), 10), "$gte": strconv.FormatInt(newend, 10)}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	items = append(items, thismonthnum)

	common.Logger.Info("correct?: ", items, "l: ", l)
	if len(items) != l {
		common.Logger.Error("incorrect number of months")
		return nil
	} else {
		return items
	}
	//session := pl.pool.AcquireSession()
	//defer session.Release()
	//
	//c := session.DB("blockchain").C(subname)
	//
	//var items []int
	//endtime := time.Now()
	////starttime := endtime.AddDate(-1, 0, 0)
	//month := int(endtime.Month())
	//days := endtime.Day()
	//var newstart, newend int64
	//for i := month - 1; i > 0; i-- { //今年第一个月到现在的前一个月的日志数量
	//	newstart = endtime.AddDate(0, -i, -days+1).Unix()
	//	newend = endtime.AddDate(0, -i+1, -days).Unix()
	//
	//	if newend > endtime.Unix() {
	//		common.Logger.Error("out of time range")
	//		break
	//	}
	//
	//	num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
	//	if err != nil {
	//		common.Logger.Error(err)
	//	}
	//
	//	items = append(items, num)
	//}
	////从月初到now的日志数量
	//thismonth := endtime.AddDate(0, 0, -days+1).Unix()
	//thismonthnum, err := c.Find(bson.M{"timestamp": bson.M{"$lte": strconv.FormatInt(endtime.Unix(), 10), "$gte": strconv.FormatInt(thismonth, 10)}}).Count()
	//if err != nil {
	//	common.Logger.Error(err)
	//}
	//items = append(items, thismonthnum)
	//
	//for j := month + 1; j <= 12; j++ {
	//	items = append(items, 0)
	//}
	//
	//if len(items) != 12 {
	//	common.Logger.Error("incorrect number of months")
	//	return nil
	//} else {
	//	return items
	//}
}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end string, l, uid int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	tmp1, _ := strconv.ParseInt(start, 10, 64)
	tmp2, _ := strconv.ParseInt(end, 10, 64)
	starttime := time.Unix(tmp1, 0).Local()
	endtime := time.Unix(tmp2, 0).Local()
	//starttime := endtime.AddDate(-1, 0, 0)
	month := int(endtime.Month())
	// days := endtime.Day()
	var newstart, newend int64
	for i := 0; i < month-1; i++ { //今年第一个月到现在的前一个月的日志数量
		newstart = starttime.AddDate(0, i, 0).Unix()
		newend = starttime.AddDate(0, i+1, 0).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}
	//从月初到now的日志数量
	// thismonth := endtime.AddDate(0, 0, -days).Unix()
	thismonthnum, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": strconv.FormatInt(endtime.Unix(), 10), "$gte": strconv.FormatInt(newend, 10)}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	items = append(items, thismonthnum)

	if len(items) != l {
		common.Logger.Error("incorrect number of months")
		return nil
	} else {
		return items
	}

	//var items []int
	//endtime := time.Now()
	////starttime := endtime.AddDate(-1, 0, 0)
	//month := int(endtime.Month())
	//days := endtime.Day()
	//var newstart, newend int64
	//for i := month - 1; i > 0; i-- { //今年第一个月到现在的前一个月的日志数量
	//	newstart = endtime.AddDate(0, -i, -days+1).Unix()
	//	newend = endtime.AddDate(0, -i+1, -days).Unix()
	//
	//	if newend > endtime.Unix() {
	//		common.Logger.Error("out of time range")
	//		break
	//	}
	//
	//	num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
	//	if err != nil {
	//		common.Logger.Error(err)
	//	}
	//
	//	items = append(items, num)
	//}
	////从月初到now的日志数量
	//thismonth := endtime.AddDate(0, 0, -days+1).Unix()
	//thismonthnum, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": strconv.FormatInt(endtime.Unix(), 10), "$gte": strconv.FormatInt(thismonth, 10)}}).Count()
	//if err != nil {
	//	common.Logger.Error(err)
	//}
	//items = append(items, thismonthnum)
	////本月之后的每月日志数量都为0
	//for j := month + 1; j <= 12; j++ {
	//	items = append(items, 0)
	//}
	////m1 := bson.M{"$match": bson.M{"username": username}}
	////m2 := bson.M{"$group": bson.M{"_id": "$action", "count": bson.M{"$sum": 1}}}
	////m3 := bson.M{"$skip": skip}
	////m4 := bson.M{"$limit": limit}
	////m5 := bson.M{"$project": bson.M{"action": "$_id", "count": 1}}
	////m6 := bson.M{"$sort": bson.M{"count": -1}}
	////err := c.Pipe([]bson.M{m1, m2, m3, m4, m5, m6}).All(&items)
	////if err != nil {
	////	log.Println(err)
	////}
	//
	//if len(items) != 12 {
	//	common.Logger.Error("incorrect number of days")
	//	return nil
	//} else {
	//	return items
	//}
}
func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end string, l, uid int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	tmp1, _ := strconv.ParseInt(start, 10, 64)
	tmp2, _ := strconv.ParseInt(end, 10, 64)
	starttime := time.Unix(tmp1, 0).Local()
	endtime := time.Unix(tmp2, 0).Local()
	//starttime := endtime.AddDate(-1, 0, 0)
	month := int(endtime.Month())
	//days := endtime.Day()
	var newstart, newend int64
	for i := 0; i < month-1; i++ { //今年第一个月到现在的前一个月的日志数量
		newstart = starttime.AddDate(0, i, 0).Unix()
		newend = starttime.AddDate(0, i+1, 0).Unix()

		if newend > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": strconv.FormatInt(newend, 10), "$gte": strconv.FormatInt(newstart, 10)}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}
	//从月初到now的日志数量
	// thismonth := endtime.AddDate(0, 0, -days).Unix()
	thismonthnum, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": strconv.FormatInt(endtime.Unix(), 10), "$gte": strconv.FormatInt(newend, 10)}}).Count()
	if err != nil {
		common.Logger.Error(err)
	}
	items = append(items, thismonthnum)

	if len(items) != l {
		common.Logger.Error("incorrect number of months")
		return nil
	} else {
		return items
	}
}
func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseByDay() []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	endtime := time.Now()
	starttime := endtime.AddDate(0, 0, -1)
	dur := int(endtime.Sub(starttime).Hours())

	t := starttime.Unix()
	var newstart, newend string
	for i := 0; i < dur; i++ {
		newstart = strconv.FormatInt(t+int64(i*3600), 10)
		newend = strconv.FormatInt(t+int64((i+1)*3600), 10)

		if t+int64((i+1)*3600) > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}

	if len(items) != dur {
		common.Logger.Error("incorrect number of hours")
		return nil
	} else {
		return items
	}
}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseByDay() []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	endtime := time.Now()
	starttime := endtime.AddDate(0, 0, -1)
	dur := int(endtime.Sub(starttime).Hours())

	t := starttime.Unix()

	var newstart, newend string
	for i := 0; i < dur; i++ {
		newstart = strconv.FormatInt(t+int64(i*3600), 10)
		newend = strconv.FormatInt(t+int64((i+1)*3600), 10)

		if t+int64((i+1)*3600) > endtime.Unix() {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}

	if len(items) != dur {
		common.Logger.Error("incorrect number of hours")
		return nil
	} else {
		return items
	}
}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabase(start, end string, l int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(newstart, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	for i := 0; i < l; i++ {
		newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
		newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

		if t+int64((i+1)*3600*24) > endtime {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}
	//m1 := bson.M{"$match": bson.M{"username": username}}
	//m2 := bson.M{"$group": bson.M{"_id": "$action", "count": bson.M{"$sum": 1}}}
	//m3 := bson.M{"$skip": skip}
	//m4 := bson.M{"$limit": limit}
	//m5 := bson.M{"$project": bson.M{"action": "$_id", "count": 1}}
	//m6 := bson.M{"$sort": bson.M{"count": -1}}
	//err := c.Pipe([]bson.M{m1, m2, m3, m4, m5, m6}).All(&items)
	//if err != nil {
	//	log.Println(err)
	//}

	if len(items) != l {
		common.Logger.Error("incorrect number of days")
		return nil
	} else {
		return items
	}
}

func getMonth(t int64) string { //从时间戳获取月份
	tFormat := time.Unix(t, 0).Format("01/02/2006 15:04:05")
	month := string(tFormat[0]) + string(tFormat[1])
	return month
}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseDaysOrMonth(start, end string, l int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(start, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	tmp1 := time.Unix(t, 0).Local()
	tmp2 := time.Unix(endtime, 0).Local()

	startmonth := int(tmp1.Month())
	endmonth := int(tmp2.Month())
	dur := (endtime - t) / (3600 * 24)
	// common.Logger.Info("第一次处理时间:", "startmonth:", startmonth, "endmonth:", endmonth)

	// common.Logger.Info("start:", tmp1, "end:", tmp2, "dur:", dur)

	if l == 7 { //分析周度，当num等于7时可能是周、月、年
		if dur <= 7 || startmonth == endmonth { //end - start 小于 7天的话那就是周
			for i := 0; i < l; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}
		} else { //end - start 大于 7天，开始和结束月份不相同就是年度
			items = pl.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end, l)
		}
	} else if l == 1 { //当num等于1时，月度和年度是一样的，因为开始和结束的月份都一样
		items = pl.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end, l) //直接获取年度日志数量
	} else { //其他情况就是月度和年度的判断
		if startmonth == endmonth { // 如果开始和结束月份相同，则是这个月的
			for i := 0; i < l-1; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}
			numlast, _ := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": newend}}).Count()
			items = append(items, numlast)
		} else { //获取年度日志数量
			items = pl.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end, l)
		}
	}

	return items

}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseDaysOrMonth(start, end string, l int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(start, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	tmp1 := time.Unix(t, 0).Local()
	tmp2 := time.Unix(endtime, 0).Local()

	startmonth := int(tmp1.Month())
	endmonth := int(tmp2.Month())
	dur := (endtime - t) / (3600 * 24)
	// common.Logger.Info("第一次处理时间:", "startmonth:", startmonth, "endmonth:", endmonth)

	if l == 7 { //分析周度，当num等于7时可能是周、月、年
		if dur <= 7 || startmonth == endmonth { //end - start 小于 7天的话那就是周或者月，这俩是一样的
			for i := 0; i < l; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}
		} else { //end - start 大于 7天，开始和结束月份不相同就是年度
			items = pl.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end, l)
		}
	} else if l == 1 { //当num等于1时，月度和年度是一样的，因为开始和结束的月份都一样
		items = pl.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end, l) //直接获取年度日志数量
	} else { //其他情况就是月度和年度的判断
		if startmonth == endmonth { // 如果开始和结束月份相同，则是这个月的
			for i := 0; i < l-1; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}
			numlast, _ := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": newend}}).Count()
			items = append(items, numlast)
		} else { //获取年度日志数量
			items = pl.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonth(start, end, l)
		}
	}

	return items

}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseDaysOrMonthByUGroupID(start, end string, l, uid int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(newstart, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}
	tmp1 := time.Unix(t, 0).Local()
	tmp2 := time.Unix(endtime, 0).Local()

	startmonth := int(tmp1.Month())
	endmonth := int(tmp2.Month())
	dur := (endtime - t) / (3600 * 24)

	if l == 7 { //分析周度，当num等于7时可能是周、月、年
		if dur <= 7 || startmonth == endmonth { //end - start 小于 7天的话那就是周或月
			for i := 0; i < l; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}

		} else { //end - start 大于 7天，开始和结束月份不相同就是年度
			items = pl.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end, l, uid)
		}
	} else if l == 1 { //当num等于1时，月度和年度是一样的，因为开始和结束的月份都一样
		items = pl.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end, l, uid) //直接获取年度日志数量
	} else { //其他情况就是月度和年度的判断
		if startmonth == endmonth { // 如果开始和结束月份相同，则是这个月的
			for i := 0; i < l-1; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}
			numlast, _ := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": end, "$gte": newend}}).Count()
			items = append(items, numlast)

		} else { //获取年度日志数量
			items = pl.GetNormalLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end, l, uid)
		}
	}

	return items

}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseDaysOrMonthByUGroupID(start, end string, l, uid int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(newstart, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	tmp1 := time.Unix(t, 0).Local()
	tmp2 := time.Unix(endtime, 0).Local()

	startmonth := int(tmp1.Month())
	endmonth := int(tmp2.Month())
	dur := (endtime - t) / (3600 * 24)

	if l == 7 { //分析周度，当num等于7时可能是周、月、年
		if dur <= 7 || startmonth == endmonth { //end - start 小于 7天的话那就是周或月
			for i := 0; i < l; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}
			numlast, _ := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": end, "$gte": newend}}).Count()
			items = append(items, numlast)
		} else { //end - start 大于 7天，开始和结束月份不相同就是年度
			items = pl.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end, l, uid)
		}
	} else if l == 1 { //当num等于1时，月度和年度是一样的，因为开始和结束的月份都一样
		items = pl.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end, l, uid) //直接获取年度日志数量
	} else { //其他情况就是月度和年度的判断
		if startmonth == endmonth { // 如果开始和结束月份相同，则是这个月的
			for i := 0; i < l-1; i++ {
				newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
				newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

				if t+int64((i+1)*3600*24) > endtime {
					common.Logger.Error("out of time range")
					break
				}

				num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
				if err != nil {
					common.Logger.Error(err)
				}

				items = append(items, num)
			}
			numlast, _ := c.Find(bson.M{"timestamp": bson.M{"$lte": end, "$gte": newend}}).Count()
			items = append(items, numlast)
		} else { //获取年度日志数量
			items = pl.GetWarningLogsAnalysisFromDatabaseTillNowMonthByMonthByUGroupID(start, end, l, uid)
		}
	}

	return items

}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabase(start, end string, l int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(newstart, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	for i := 0; i < l; i++ {
		newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
		newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

		if t+int64((i+1)*3600*24) > endtime {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}

	if len(items) != l {
		common.Logger.Error("incorrect number of days")
		return nil
	} else {
		return items
	}

	//var items []LogAnalysis
	//c := session.DB("blockchain").C(subname)
	//m1 := bson.M{"$match": bson.M{"username": username}}
	//m2 := bson.M{"$group": bson.M{"_id": "$action", "count": bson.M{"$sum": 1}}}
	//err := c.Pipe([]bson.M{m1, m2}).All(&items)
	//if err != nil {
	//	log.Println(err)
	//}
	//return len(items)
}

func (pl *Mongo) GetNormalLogsAnalysisFromDatabaseByUGroupID(start, end string, l int, uid int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(newstart, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	for i := 0; i < l; i++ {
		newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
		newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

		if t+int64((i+1)*3600*24) > endtime {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}
	//m1 := bson.M{"$match": bson.M{"username": username}}
	//m2 := bson.M{"$group": bson.M{"_id": "$action", "count": bson.M{"$sum": 1}}}
	//m3 := bson.M{"$skip": skip}
	//m4 := bson.M{"$limit": limit}
	//m5 := bson.M{"$project": bson.M{"action": "$_id", "count": 1}}
	//m6 := bson.M{"$sort": bson.M{"count": -1}}
	//err := c.Pipe([]bson.M{m1, m2, m3, m4, m5, m6}).All(&items)
	//if err != nil {
	//	log.Println(err)
	//}

	if len(items) != l {
		common.Logger.Error("incorrect number of days")
		return nil
	} else {
		return items
	}

}

func (pl *Mongo) GetWarningLogsAnalysisFromDatabaseByUGroupID(start, end string, l int, uid int) []int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog-Warning"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var items []int
	newstart := start
	newend := end
	endtime, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	t, err := strconv.ParseInt(newstart, 10, 64)
	if err != nil {
		common.Logger.Error(err)
	}

	for i := 0; i < l; i++ {
		newstart = strconv.FormatInt(t+int64(i*3600*24), 10)
		newend = strconv.FormatInt(t+int64((i+1)*3600*24), 10)

		if t+int64((i+1)*3600*24) > endtime {
			common.Logger.Error("out of time range")
			break
		}

		num, err := c.Find(bson.M{"ugroupid": uid, "timestamp": bson.M{"$lte": newend, "$gte": newstart}}).Count()
		if err != nil {
			common.Logger.Error(err)
		}

		items = append(items, num)
	}

	if len(items) != l {
		common.Logger.Error("incorrect number of days")
		return nil
	} else {
		return items
	}

	//var items []LogAnalysis
	//c := session.DB("blockchain").C(subname)
	//m1 := bson.M{"$match": bson.M{"username": username}}
	//m2 := bson.M{"$group": bson.M{"_id": "$action", "count": bson.M{"$sum": 1}}}
	//err := c.Pipe([]bson.M{m1, m2}).All(&items)
	//if err != nil {
	//	log.Println(err)
	//}
	//return len(items)
}

func (pl *Mongo) GetPageLogsByIdentityAndRangeTimeFromDatabase(identityidentifier, start, end string, skip, limit int) []MetaData.UserLog {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var items []MetaData.UserLog
	c := session.DB("blockchain").C(subname)

	err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier), "timestamp": bson.M{"$lte": end, "$gte": start}}).Sort("-timestamp").Skip(skip).Limit(limit).All(&items)
	if err != nil {
		log.Println(err)
	}
	return decryptAllUserLog(items)
}

func (pl *Mongo) GetPageLogsCountByIdentityAndRangeTimeFromDatabase(identityidentifier, start, end string) int {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	var total int
	c := session.DB("blockchain").C(subname)

	total, err := c.Find(bson.M{"identityidentifier": utils.EncryptString(identityidentifier), "timestamp": bson.M{"$lte": end, "$gte": start}}).Count()
	if err != nil {
		log.Println(err)
	}
	return total
}

func (pl *Mongo) GetExtranetLogsAnalysisByUser(time string) (map[string]int, error) {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var result []struct {
		Id    string "_id"
		Value int
	}

	job := &mgo.MapReduce{
		Map:    "function() { emit(this.name, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}
	//1638520560000
	_, err := c.Find(bson.M{"isinner": 0, "timestamp": bson.M{"$gte": time}}).MapReduce(job, &result)
	if err != nil {
		common.Logger.Error(err)
		return nil, err
	}

	analysis := make(map[string]int)
	for _, item := range result {
		if item.Id == "" {
			continue
		}
		if utils.DecryptString(item.Id) == "" {
			continue
		}
		analysis[utils.DecryptString(item.Id)] = item.Value
	}
	return analysis, nil
}

func (pl *Mongo) GetExtranetLogsAnalysisByWebsite(time string) (map[string]int, error) {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var result []struct {
		Id    string "_id"
		Value int
	}

	job := &mgo.MapReduce{
		Map:    "function() { emit(this.website, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}

	_, err := c.Find(bson.M{"isinner": 0, "timestamp": bson.M{"$gte": time}}).MapReduce(job, &result)
	if err != nil {
		common.Logger.Error(err)
		return nil, err
	}

	analysis := make(map[string]int)
	for _, item := range result {
		if item.Id == "" {
			continue
		}
		if utils.DecryptString(item.Id) == "" {
			continue
		}
		analysis[utils.DecryptString(item.Id)] = item.Value
	}
	return analysis, nil
}

func (pl *Mongo) GetExtranetLogsAnalysisByUserAndUGroupID(uid int, time string) (map[string]int, error) {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var result []struct {
		Id    string "_id"
		Value int
	}

	job := &mgo.MapReduce{
		Map:    "function() { emit(this.name, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}

	_, err := c.Find(bson.M{"isinner": 0, "ugroupid": uid, "timestamp": bson.M{"$gte": time}}).MapReduce(job, &result)
	if err != nil {
		common.Logger.Error(err)
		return nil, err
	}

	analysis := make(map[string]int)
	for _, item := range result {
		if item.Id == "" {
			continue
		}
		if utils.DecryptString(item.Id) == "" {
			continue
		}
		analysis[utils.DecryptString(item.Id)] = item.Value
	}
	return analysis, nil
}

func (pl *Mongo) GetExtranetLogsAnalysisByWebsiteAndUGroupID(uid int, time string) (map[string]int, error) {
	index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(pl.Pubkey))))
	subname := index + "-" + "UserLog"
	session := pl.pool.AcquireSession()
	defer session.Release()

	c := session.DB("blockchain").C(subname)

	var result []struct {
		Id    string "_id"
		Value int
	}

	job := &mgo.MapReduce{
		Map:    "function() { emit(this.filterwebsite, 1) }",
		Reduce: "function(key, values) { return Array.sum(values) }",
	}

	_, err := c.Find(bson.M{"isinner": 0, "ugroupid": uid, "timestamp": bson.M{"$gte": time}}).MapReduce(job, &result)
	if err != nil {
		common.Logger.Error(err)
		return nil, err
	}

	analysis := make(map[string]int)
	for _, item := range result {
		if item.Id == "" {
			continue
		}
		if utils.DecryptString(item.Id) == "" {
			continue
		}
		analysis[utils.DecryptString(item.Id)] = item.Value
	}
	return analysis, nil
}

func decryptAllUserLog(sources []MetaData.UserLog) []MetaData.UserLog {
	var results []MetaData.UserLog

	for _, logs := range sources {
		results = append(results, decryptUserLog(logs))
	}

	return results
}

func decryptUserLog(source MetaData.UserLog) MetaData.UserLog {
	result := MetaData.UserLog{}

	result.IdentityIdentifier = checkUserlogforDecrypt(source.IdentityIdentifier)
	result.Command = checkUserlogforDecrypt(source.Command)
	result.Name = checkUserlogforDecrypt(source.Name)
	result.UGroupID = source.UGroupID

	result.Source = checkUserlogforDecrypt(source.Source)
	result.Timestamp = source.Timestamp
	result.Data = checkUserlogforDecrypt(source.Data)
	result.Level = source.Level
	result.Permission = checkUserlogforDecrypt(source.Permission)
	result.WarnInfo = checkUserlogforDecrypt(source.WarnInfo)
	result.WebSite = checkUserlogforDecrypt(source.WebSite)
	result.FilterWebSite = checkUserlogforDecrypt(source.FilterWebSite)
	result.Destination = checkUserlogforDecrypt(source.Destination)
	result.Protocol = checkUserlogforDecrypt(source.Protocol)
	result.IsInner = source.IsInner

	return result
}

func encryptUserLog(source MetaData.UserLog) MetaData.UserLog {
	result := MetaData.UserLog{}

	result.IdentityIdentifier = checkUserlogforEncrypt(source.IdentityIdentifier)
	result.Command = checkUserlogforEncrypt(source.Command)
	result.Name = checkUserlogforEncrypt(source.Name)
	result.UGroupID = source.UGroupID

	result.Source = checkUserlogforEncrypt(source.Source)
	result.Timestamp = source.Timestamp
	result.Data = checkUserlogforEncrypt(source.Data)
	result.Level = source.Level
	result.Permission = checkUserlogforEncrypt(source.Permission)
	result.WarnInfo = checkUserlogforEncrypt(source.WarnInfo)
	result.WebSite = checkUserlogforEncrypt(source.WebSite)
	result.FilterWebSite = checkUserlogforEncrypt(source.FilterWebSite)
	result.Destination = checkUserlogforEncrypt(source.Destination)
	result.Protocol = checkUserlogforEncrypt(source.Protocol)
	result.IsInner = source.IsInner
	fmt.Println("上传的的用户身日志为：", result)

	return result
}

func checkUserlogforEncrypt(source string) string {
	var result string
	if source == "" {
		result = ""
	} else {
		result = utils.EncryptString(source)
	}
	return result
}

func checkUserlogforDecrypt(source string) string {
	var result string
	if source == "" {
		result = ""
	} else {
		result = utils.DecryptString(source)
	}
	return result
}
