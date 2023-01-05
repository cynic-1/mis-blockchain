package Node

import (
	"MIS-BC/MetaData"
	"MIS-BC/Network"
	"MIS-BC/common"
	"fmt"
	"minlib/minsecurity/crypto/cert"
	"time"
)

func (node *Node) UpdateVariables(bg *MetaData.BlockGroup) {
	if bg.Height > 0 { //normal blockgroup
		node.dutyWorkerNumber = bg.NextDutyWorker
		node.StartTime = bg.Timestamp

		node.BCStatus.Mutex.Lock()
		node.BCStatus.BgsList.PushBack(*bg)
		if node.BCStatus.BgsList.Len() > 10 {
			i1 := node.BCStatus.BgsList.Front()
			node.BCStatus.BgsList.Remove(i1)
		}
		node.BCStatus.Mutex.Unlock()

		for i, eachBlock := range bg.Blocks {
			if len(bg.VoteResult) <= i {
				continue
			}
			if bg.VoteResult[i] != 1 {
				continue
			}
			node.TxsPeriodAmount = uint64(len(eachBlock.Transactions))
			for _, eachTransaction := range eachBlock.Transactions {
				transactionHeader, transactionInterface := MetaData.DecodeTransaction(eachTransaction)
				node.UpdateTransactionVariables(transactionHeader.TXType, eachTransaction)
				switch transactionHeader.TXType {
				case MetaData.IdentityAction:
					node.UpdateIdentityVariables(transactionInterface)
				case MetaData.IdTransformation:
					node.UpdateIdTransformationVaribles(transactionInterface)
				case MetaData.UserLogOperation:
					node.UpdateUserLogVariables(transactionInterface)
				case MetaData.CRSRecordOperation:
					common.Logger.Info("crs block: ", eachBlock.Height, eachBlock.BlockNum)
					node.UpdateCRSRecordVariables(transactionInterface, eachBlock.Height, eachBlock.BlockNum)
				}
			}
			node.TxsAmount += uint64(len(eachBlock.Transactions))

			node.BCStatus.Mutex.Lock()

			if bg.Height > 0 {
				node.BCStatus.Overview.Height = int64(bg.Height)
				node.BCStatus.Overview.TransactionNum = node.TxsAmount
				node.BCStatus.Overview.ProcessingTransactionNum = node.TxsPeriodAmount
				node.BCStatus.Overview.NodeNum = len(node.BCStatus.Nodes)
				fmt.Println(node.BCStatus.TxsNumList.Back().Value, "...", node.BCStatus.Overview.TransactionNum)
				node.BCStatus.TxsNumList.Back().Value = node.BCStatus.Overview.TransactionNum - node.BCStatus.Overview.PreTransactionNum
				var ta MetaData.TransactionAnalysis
				for j := node.BCStatus.TxsNumList.Front(); j != nil; j = j.Next() {
					ta.TxsList = append(ta.TxsList, j.Value.(uint64))
				}
				ta.TxsNum = node.BCStatus.Overview.TransactionNum
				ta.PreTxsNum = node.BCStatus.Overview.PreTransactionNum
				common.Logger.Info("overview info: ", node.BCStatus.Overview, "\ttransactionanalysis:", ta)

				var cr []interface{}
				for j := node.BCStatus.TxsList.Front(); j != nil; j = j.Next() {
					if j.Value != nil {
						if transaction, ok := j.Value.(MetaData.Identity); ok {
							cr = append(cr, transaction)
						}
						if transaction, ok := j.Value.(MetaData.UserLog); ok {
							cr = append(cr, transaction)
						}
						if transaction, ok := j.Value.(MetaData.CrsChainRecord); ok {
							cr = append(cr, transaction)
						}
					} else {
						cr = append(cr, MetaData.CrsChainRecord{})
					}
				}

				var heights []int
				var bgs []MetaData.BlockGroup
				for j := node.BCStatus.BgsList.Front(); j != nil; j = j.Next() {
					if j.Value != nil {
						bgs = append(bgs, j.Value.(MetaData.BlockGroup))
						heights = append(heights, (j.Value.(MetaData.BlockGroup)).Height)
					} else {
						bgs = append(bgs, MetaData.BlockGroup{})
					}
				}
				common.Logger.Info("transaction list:", cr)

				node.mongo.SaveTransactionAnalysisToDatabase(ta)

				var tlist []MetaData.CrsChainRecord
				for j := node.BCStatus.TxsList.Front(); j != nil; j = j.Next() {
					if j.Value != nil {
						tlist = append(tlist, j.Value.(MetaData.CrsChainRecord))
					}
				}
				//node.mongo.SaveTransactionListToDatabase(tlist)
			}
			node.BCStatus.Mutex.Unlock()
		}
	} else {
		fmt.Println("更新变量错误")
	}

	node.UpdateIdTransOk()
}

func (node *Node) UpdateTransactionVariables(transactionType int, transaction []byte) {
	node.mongo.SaveTransactionToDatabase(transactionType, string(transaction))
}

func (node *Node) UpdateIdentityVariables(transactionInterface MetaData.TransactionInterface) {
	if transaction, ok := transactionInterface.(*MetaData.Identity); ok {
		node.BCStatus.Mutex.Lock()
		tmp := *transaction
		trans := &tmp
		trans.Timestamp = time.Now().Format("2006-01-02 15:04:05")
		node.BCStatus.TxsList.PushBack(trans)
		if node.BCStatus.TxsList.Len() > 10 {
			i1 := node.BCStatus.TxsList.Front()
			node.BCStatus.TxsList.Remove(i1)
		}

		var txs []interface{}
		for i := node.BCStatus.TxsList.Front(); i != nil; i = i.Next() {
			txs = append(txs, i.Value)
		}
		common.Logger.Info("txs:", txs)
		// TODO: 内存里没有存储最近四个交易时，回去像数据库中获取

		node.BCStatus.Mutex.Unlock()

		switch transaction.Command {
		case "Registry":
			node.mongo.SaveIdentityToDatabase(*transaction)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "申请注册成功")
		case "DestroyByIdentityIdentifier":
			if node.mongo.HasIdentityData("identityidentifier", transaction.IdentityIdentifier) {
				i := node.mongo.GetOneIdentityFromDatabase("identityidentifier", transaction.IdentityIdentifier)
				flag, err := node.network.Keychain.DeleteIdentityByName(transaction.IdentityIdentifier, i.Passwd)
				if err != nil {
					common.Logger.Error(err)
				} else if flag == true {
					common.Logger.Info("sqlite删除身份成功")
				} else {
					common.Logger.Info("sqlite删除身份失败")
				}
				node.mongo.DeleteIdentity("identityidentifier", transaction.IdentityIdentifier)
				node.RegistryCache.Delete(transaction.IdentityIdentifier)
				common.Logger.Info("身份", transaction.IdentityIdentifier, "删除成功")
			} else {
				common.Logger.Info("身份", transaction.IdentityIdentifier, "不存在")
			}
		case "ResetPassword":
			identity := node.mongo.GetOneIdentityFromDatabase("identityidentifier", transaction.IdentityIdentifier)
			cert := cert.Certificate{}
			err := cert.FromPem(identity.Cert, []byte(identity.Passwd), 0)
			if err != nil {
				common.Logger.Error(err)
				return
			}
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.ResetIdentityPassword(transaction.Passwd, item)

			c, err := cert.ToPem([]byte(transaction.Passwd), 0)
			if err != nil {
				common.Logger.Error(err)
				return
			}
			node.mongo.ResetIdentityCert(c, item)
			//item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			//node.mongo.ResetIdentityPassword(transaction.Passwd, item)
			//node.mongo.ResetIdentityEncryptedPrikey(transaction.PrikeyEncrypted, item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "密码修改成功")
		case "ResetIPIdentifier":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.ResetIdentityIPIdentifier(transaction.IPIdentifier, item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "IP更新成功")
		case "EnableIdentity":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.EnableIdentity(transaction.IsValid, transaction.Cert, item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "审核成功")
		case "ResetValidation":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.ResetIdentityValidation(transaction.IsValid, item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "有效性变更成功")
		case "CertRevocation":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.CertRevocation(item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "证书撤销成功")
		case "CertReissue":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.CertReissue(transaction.Cert, item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "证书重新颁发成功")
		case "UploadPhone":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.UploadIdentityPhone(transaction.Phone, item)
			common.Logger.Info("身份", transaction.Phone, "手机号上传成功")
		case "UploadEncryptedPrikey":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.UploadIdentityEncryptedPrikey(transaction.PrikeyEncrypted, transaction.Phone, item)
			common.Logger.Info("身份", transaction.PrikeyEncrypted, "私钥上传成功")
		case "BindWeChat":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.UploadIdentityWeChat(transaction.WXUnionID, item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "微信绑定成功")
		case "UnboundWeChat":
			item := node.mongo.GetOneIdentityMapFromDatabase(transaction.IdentityIdentifier)
			node.mongo.UploadIdentityWeChat(transaction.WXUnionID, item)
			common.Logger.Info("身份", transaction.IdentityIdentifier, "微信解绑成功")
		}
	}
}

func (node *Node) UpdateUserLogVariables(transactionInterface MetaData.TransactionInterface) {
	if transaction, ok := transactionInterface.(*MetaData.UserLog); ok {
		node.BCStatus.Mutex.Lock()
		tmp := *transaction
		trans := &tmp
		trans.Timestamp = time.Now().Format("2006-01-02 15:04:05")
		node.BCStatus.TxsList.PushBack(trans)
		if node.BCStatus.TxsList.Len() > 10 {
			i1 := node.BCStatus.TxsList.Front()
			node.BCStatus.TxsList.Remove(i1)
		}
		node.BCStatus.Mutex.Unlock()
		switch transaction.Command {
		case "UploadNormalUserLog":
			node.mongo.SaveNormalUserLogToDatabase(*transaction)
			common.Logger.Info(transaction.IdentityIdentifier, "普通日志", transaction.Data, "记录成功")
		case "UploadWarningUserLog":
			node.mongo.SaveWarningUserLogToDatabase(*transaction)
			common.Logger.Info(transaction.IdentityIdentifier, "告警日志", transaction.Data, "记录成功")
		}
	}
}

func (node *Node) UpdateCRSRecordVariables(transactionInterface MetaData.TransactionInterface, height int, blockNum uint32) {
	if transaction, ok := transactionInterface.(*MetaData.CrsChainRecord); ok {
		node.BCStatus.Mutex.Lock()
		tmp := *transaction
		//trans := &tmp
		node.BCStatus.TxsList.PushBack(tmp)
		if node.BCStatus.TxsList.Len() > 10 {
			i1 := node.BCStatus.TxsList.Front()
			node.BCStatus.TxsList.Remove(i1)
		}
		node.BCStatus.Mutex.Unlock()
		go node.SendHeightofBlock(height, blockNum, transaction.TransactionHash)
		node.mongo.SaveCRSRecordToDatabase(*transaction)
		common.Logger.Info(transaction.Data, "记录成功")
	}
}

func (node *Node) UpdateIdTransformationVaribles(transactionInterface MetaData.TransactionInterface) {
	if transaction, ok := transactionInterface.(*MetaData.IdentityTransformation); ok {
		node.BCStatus.Mutex.Lock()
		tmp := *transaction
		trans := &tmp
		trans.Timestamp = time.Now().Unix()
		node.BCStatus.TxsList.PushBack(trans)
		if node.BCStatus.TxsList.Len() > 10 {
			i1 := node.BCStatus.TxsList.Front()
			node.BCStatus.TxsList.Remove(i1)
		}
		node.BCStatus.Mutex.Unlock()
		switch transaction.Type {

		case "ApplyNode": //apply for voter and worker
			_, ok := node.accountManager.VoterSet[transaction.Pubkey]
			if ok {
				fmt.Println("申请成为投票节点失败，已经是投票节点")
				return
			}
			_, ok = node.accountManager.WorkerCandidateSet[transaction.Pubkey]
			if ok {
				fmt.Println("申请成为候选记账节点失败，已经是候选记账节点")
				return
			}
			ok = node.mongo.HasData("identity", "pubkey", transaction.Pubkey)
			if ok {
				fmt.Println("已经接收到该用户请求")
				return
			}
			node.network.AddNodeToNodeList(transaction.GetNodeId(), transaction.IPAddr, transaction.Port)
			node.mongo.SaveNodeIdentityTransToDatabase(*transaction)
			fmt.Println(transaction.GetNodeId(), "申请成为投票节点成功")

		case "IamOk":
			_, ok := node.accountManager.VoterSet[transaction.Pubkey]
			if ok {
				fmt.Println("申请成为投票节点失败，已经是投票节点")
				return
			}
			_, ok = node.accountManager.WorkerCandidateSet[transaction.Pubkey]
			if ok {
				fmt.Println("申请成为候选记账节点失败，已经是候选记账节点")
				return
			}
			if !node.mongo.HasData("identity", "pubkey", transaction.Pubkey) {
				fmt.Println("无法查到该节点的申请信息")
				return
			}

			identity := node.mongo.GetOneNodeIdentityTransFromDatabase("identity", "pubkey", transaction.Pubkey)
			identity.Type = "IamOk"
			identity.Timestamp = time.Now().Unix()

			/*_, ok = node.IdentityTransList[identity]
			if ok{
				fmt.Println("已经接收到该节点加入请求")
				return
			}*/

			node.IdentityTransList[identity] = node.mongo.GetHeight() + 3
			fmt.Println("新节点申请加入成功")
			var nodelist MetaData.NodeList
			nodelist.SetNodeList(node.network.NodeList)
			node.mongo.InsertOrUpdateNodeList(nodelist)

			var identityTransList MetaData.IdentityTransList
			identityTransList.SetIdentityTransList(node.IdentityTransList)
			node.mongo.InsertOrUpdateIdentityTransList(identityTransList)
		case "IamBack":
			if node.mongo.HasData("identity", "pubkey", transaction.Pubkey) {
				id := node.mongo.GetOneNodeIdentityTransFromDatabase("identity", "pubkey", transaction.Pubkey)
				if id.Type == transaction.Type {
					fmt.Println("已经收到该节点的退出请求")
					return
				}
			}

			_, ok := node.accountManager.VoterSet[transaction.Pubkey]
			if !ok {
				fmt.Println("申请退出投票节点失败，不是投票节点")
				return
			}
			_, ok = node.accountManager.WorkerCandidateSet[transaction.Pubkey]
			if !ok {
				fmt.Println("申请退出候选记账节点失败，不是候选记账节点")
				return
			}
			node.mongo.SaveNodeIdentityTransToDatabase(*transaction)
			node.IdentityTransList[*transaction] = node.mongo.GetHeight() + 3
			fmt.Println("新节点申请退出成功")

		case "ApplyForVoter":
			_, ok := node.accountManager.VoterSet[transaction.Pubkey]
			if !ok {
				node.accountManager.VoterSet[transaction.Pubkey] = transaction.GetNodeId()
			} else {
				fmt.Println("申请成为投票节点失败，已经是投票节点")
			}
			_, ok = node.network.NodeList[transaction.GetNodeId()]
			if !ok {
				var nodelist Network.NodeInfo
				nodelist.IP = transaction.IPAddr
				nodelist.PORT = transaction.Port
				nodelist.ID = transaction.GetNodeId()
				node.network.NodeList[transaction.GetNodeId()] = nodelist
			}
		case "ApplyForWorkerCandidate":
			_, ok := node.accountManager.WorkerCandidateSet[transaction.Pubkey]
			if !ok {
				node.accountManager.WorkerCandidateSet[transaction.Pubkey] = transaction.GetNodeId()
			} else {
				fmt.Println("申请成为候选记账节点失败，已经是候选记账节点")
			}
			_, ok = node.network.NodeList[transaction.GetNodeId()]
			if !ok {
				var nodelist Network.NodeInfo
				nodelist.IP = transaction.IPAddr
				nodelist.PORT = transaction.Port
				nodelist.ID = transaction.GetNodeId()
				node.network.NodeList[transaction.GetNodeId()] = nodelist
			}
		case "QuitVoter":
			delete(node.accountManager.VoterSet, transaction.Pubkey)
			delete(node.network.NodeList, transaction.GetNodeId())
			fmt.Println("退出投票节点成功")
		case "QuitWorkerCandidate":
			delete(node.accountManager.WorkerCandidateSet, transaction.Pubkey)
			delete(node.network.NodeList, transaction.GetNodeId())
			fmt.Println("退出候选记账节点成功")
		}
	}
}

func (node *Node) UpdateIdTransOk() {
	for k, v := range node.IdentityTransList {
		if v == node.mongo.GetHeight() {
			if k.Type == "IamOk" {
				_, ok := node.accountManager.VoterSet[k.Pubkey]
				flag := true
				if ok {
					flag = false
					fmt.Println(node.accountManager.VoterNumberSet)
					fmt.Println(node.accountManager.VoterSet)
					fmt.Println("申请成为投票节点失败，已经是投票节点")
				}
				_, ok = node.accountManager.WorkerCandidateSet[k.Pubkey]
				if ok {
					flag = false
					fmt.Println("申请成为候选记账节点失败，已经是候选记账节点")
				}
				if !node.mongo.HasData("identity", "pubkey", k.Pubkey) {
					flag = false
					fmt.Println("无法查到该节点的申请信息")
				}
				if flag {
					node.accountManager.VoterSet[k.Pubkey] = k.GetNodeId()

					var nums uint32 = 0
					for k, _ := range node.accountManager.VoterNumberSet {
						if nums < k {
							nums = k
						}
					}
					nums++
					node.accountManager.VoterNumberSet[nums] = k.Pubkey
					node.accountManager.WorkerCandidateSet[k.Pubkey] = k.GetNodeId()
					if len(node.accountManager.WorkerSet) < node.config.WorkerNum {
						var i = 0
						for ; i < node.config.WorkerNum; i++ {
							if _, ok := node.accountManager.WorkerNumberSet[uint32(i)]; !ok {
								node.accountManager.WorkerSet[k.Pubkey] = k.GetNodeId()
								node.accountManager.WorkerNumberSet[uint32(i)] = k.Pubkey
								break
							}
						}
					}

					var account MetaData.Account
					account.SetVoterSet(node.accountManager.VoterSet)
					account.SetWorkerSet(node.accountManager.WorkerSet)
					account.SetWorkerCandidateSet(node.accountManager.WorkerCandidateSet)
					account.WorkerCandidateList = node.accountManager.WorkerCandidateList
					account.SetVoterNumberSet(node.accountManager.VoterNumberSet)
					account.SetWorkerNumberSet(node.accountManager.WorkerNumberSet)
					node.mongo.InsertOrUpdateAccount(account)
					node.mongo.DeleteData("identity", "pubkey", k.Pubkey)
					fmt.Println("新节点列表更新成功")
				}
				delete(node.IdentityTransList, k)
			} else if k.Type == "IamBack" {
				flag := true
				_, ok := node.accountManager.VoterSet[k.Pubkey]
				if !ok {
					fmt.Println("申请退出投票节点失败，不是投票节点")
					flag = false
				}
				_, ok = node.accountManager.WorkerCandidateSet[k.Pubkey]
				if !ok {
					fmt.Println("申请退出候选记账节点失败，不是候选记账节点")
					flag = false
				}
				if !node.mongo.HasDataByTwoKey("identity", "pubkey", k.Pubkey, "type", k.Type) {
					fmt.Println("没有查到该节点的退出请求")
					flag = false
				}
				if flag {
					fmt.Println("transaction", k)
					fmt.Println(node.accountManager.WorkerNumberSet)
					delete(node.accountManager.WorkerSet, k.Pubkey)
					delete(node.accountManager.WorkerCandidateSet, k.Pubkey)
					delete(node.accountManager.VoterSet, k.Pubkey)

					var voterNum uint32 = 0
					var max uint32 = 0
					for k1, v1 := range node.accountManager.VoterNumberSet {
						if v1 == k.Pubkey {
							voterNum = k1
							delete(node.accountManager.VoterNumberSet, k1)
						}
						if k1 > max {
							max = k1
						}
					}
					if voterNum != max {
						node.accountManager.VoterNumberSet[voterNum] = node.accountManager.VoterNumberSet[max]
						delete(node.accountManager.VoterNumberSet, max)
					}

					var workerNum uint32 = 0
					var max1 uint32 = uint32(len(node.accountManager.WorkerNumberSet)) - 1
					isDel := false
					for k1, v1 := range node.accountManager.WorkerNumberSet {
						if v1 == k.Pubkey {
							workerNum = k1
							delete(node.accountManager.WorkerNumberSet, k1)
							isDel = true
						}
					}
					if workerNum != max1 && isDel {
						node.accountManager.WorkerNumberSet[workerNum] = node.accountManager.WorkerNumberSet[max1]
						delete(node.accountManager.WorkerNumberSet, max1)
					}

					if len(node.accountManager.WorkerSet) < node.config.WorkerNum && len(node.accountManager.WorkerCandidateSet) >= node.config.WorkerNum {
						for k1, v1 := range node.accountManager.WorkerCandidateSet {
							if _, ok := node.accountManager.WorkerSet[k1]; !ok {
								node.accountManager.WorkerSet[k1] = v1
								node.accountManager.WorkerNumberSet[max1] = k1
								break
							}
						}
					}

					var account MetaData.Account
					account.SetVoterSet(node.accountManager.VoterSet)
					account.SetWorkerSet(node.accountManager.WorkerSet)
					account.SetWorkerCandidateSet(node.accountManager.WorkerCandidateSet)
					account.WorkerCandidateList = node.accountManager.WorkerCandidateList
					account.SetVoterNumberSet(node.accountManager.VoterNumberSet)
					account.SetWorkerNumberSet(node.accountManager.WorkerNumberSet)
					node.mongo.InsertOrUpdateAccount(account)
					node.mongo.DeleteData("identity", "pubkey", k.Pubkey)
					node.network.RemoveNodeToNodeList(k.GetNodeId())
					fmt.Println("新节点列表更新成功")

					if node.config.MyPubkey == k.Pubkey {
						//os.Exit(0)
					}
				}
			}
		}
	}
}

func (node *Node) UpdateGenesisBlockVariables(bg *MetaData.BlockGroup) {
	if bg.Height == 0 { //genesis blockgroup
		node.dutyWorkerNumber = 0
		node.StartTime = bg.Timestamp
		if bg.Blocks[0].Height == 0 {
			transactionHeader, transactionInterface := MetaData.DecodeTransaction(bg.Blocks[0].Transactions[0])
			if transactionHeader.TXType == MetaData.Genesis {
				node.UpdateGenesisVaribles(transactionInterface)
			}
		}
		_ = node.state
		//node.state <- Normal
		node.state <- Sync
		time.Sleep(time.Second)
	} else {
		fmt.Println("更新变量错误")
	}
}

func (node *Node) UpdateGenesisVaribles(transactionInterface MetaData.TransactionInterface) {
	if genesisTransaction, ok := transactionInterface.(*MetaData.GenesisTransaction); ok {
		node.config.WorkerNum = genesisTransaction.WorkerNum
		node.config.VotedNum = genesisTransaction.VotedNum
		node.config.BlockGroupPerCycle = genesisTransaction.BlockGroupPerCycle
		node.config.Tcut = genesisTransaction.Tcut
		node.accountManager.WorkerSet = genesisTransaction.WorkerPubList
		node.accountManager.WorkerCandidateSet = genesisTransaction.WorkerCandidatePubList
		node.accountManager.VoterSet = genesisTransaction.VoterPubList
		var index uint32 = 0
		for _, key := range genesisTransaction.WorkerSet {
			node.accountManager.WorkerNumberSet[index] = key
			index = index + 1
		}
		index = 0
		for _, key1 := range genesisTransaction.VoterSet {
			node.accountManager.VoterNumberSet[index] = key1
			index = index + 1
		}
		for key2, _ := range genesisTransaction.WorkerCandidatePubList {
			node.accountManager.WorkerCandidateList = append(node.accountManager.WorkerCandidateList, key2)
		}

		index = 0
		var null [65]byte
		for _, key3 := range genesisTransaction.WorkerTCMSet {
			if key3 == null {
				index = index + 1
				continue
			}
			node.accountManager.WorkerTCMNumberSet[index] = key3
			index = index + 1
		}
	}
}

func (node *Node) UpdateVariablesFromDisk(bg *MetaData.BlockGroup) {
	if bg.Height > 0 { //normal blockgroup
		node.dutyWorkerNumber = bg.NextDutyWorker
		node.StartTime = bg.Timestamp

		//for i, eachBlock := range bg.Blocks {
		//	if bg.VoteResult[i] != 1 {
		//		continue
		//	}
		//	for _, eachTransaction := range eachBlock.Transactions {
		//		transactionHeader, transactionInterface := MetaData.DecodeTransaction(eachTransaction)
		//		switch transactionHeader.TXType {
		//		case MetaData.IdTransformation:
		//			node.UpdateIdTransformationVaribles(transactionInterface)
		//		}
		//	}
		//}
	} else {
		fmt.Println("更新变量错误")
	}

}
