package main

import (
	"MIS-BC/Blockchain"
	"MIS-BC/common"
	"strconv"

	//"MIS-BC/tcm"
	_ "encoding/binary"
	"flag"
	"fmt"
	_ "github.com/tinylib/msgp/msgp"
)

// @Title Run
// @Description 区块链启动函数
// @Param 无
// @Return 无
func Run() {
	conf := common.ParseConfig(file) //读取配置
	common.Logger.Init(&conf)
	var nodes []Node.Node //节点数组

	//创建节点并设置参数
	for i := 0; i < conf.SingleServerNodeNum; i++ {
		var parcel = conf
		var node Node.Node
		parcel.DropDatabase = dropDatabase
		parcel.SendMsgToBCMgmt = sendMsgToMgmt
		parcel.TCMSupport = tcmSupport
		parcel.TCMIndex = uint32(tcmIndex + i)
		parcel.TCMInterval = tcmInterval
		parcel.NumOfTCM = NumOfTCM
		parcel.MyPubkey = conf.PubkeyList[i]
		parcel.MyPrikey = conf.PrikeyList[i]

		//if conf.SingleServerNodeNum > 1 && conf.IsMINConn {
		//	parcel.MyAddress.Prefix = parcel.WorkerList[i].Prefix
		//} else {
		//	parcel.MyAddress.Port += i
		//	parcel.ServicePortforFE += i
		//	t, _ := strconv.Atoi(parcel.ServiceSSLPortforVPN)
		//	parcel.ServiceSSLPortforVPN = strconv.Itoa(t + i)
		//	t, _ = strconv.Atoi(parcel.ServicePortforVPN)
		//	parcel.ServicePortforVPN = strconv.Itoa(t + i)
		//}
		parcel.MyAddress.Port += i
		parcel.ServicePortforFE += i
		t, _ := strconv.Atoi(parcel.ServiceSSLPortforVPN)
		parcel.ServiceSSLPortforVPN = strconv.Itoa(t + i)
		t, _ = strconv.Atoi(parcel.ServicePortforVPN)
		parcel.ServicePortforVPN = strconv.Itoa(t + i)
		if conf.SingleServerNodeNum > 1 {
			parcel.HostName = parcel.HostName + strconv.Itoa(i+1)
		}

		m, _ := strconv.Atoi(parcel.ServiceSSLPortforVPNFE)
		parcel.ServiceSSLPortforVPNFE = strconv.Itoa(m + i)
		m, _ = strconv.Atoi(parcel.ServicePortforVPNFE)
		parcel.ServicePortforVPNFE = strconv.Itoa(m + i)

		//获取可信模块公钥，暂时关闭
		//if i == 0 && parcel.TCMSupport {
		//	if !tcm.IsTCMExist() {
		//		panic("TCM不存在或无法成功加载")
		//	}
		//	ret := tcm.Init(2)
		//	if ret != 0 {
		//		panic("tcm.Init")
		//	}
		//	ret = tcm.GetPubkey(parcel.TCMIndex, unsafe.Pointer(&(parcel.MyTCMPubKey)), unsafe.Pointer(&(parcel.MyTCMPubKeyLen)))
		//	if ret != 0 {
		//		panic("tcm.GetPubkey")
		//	}
		//
		//	fmt.Println("获取可信模块公钥成功")
		//	fmt.Println("MyTCMPubKey=", parcel.MyTCMPubKey)
		//	fmt.Println("MyTCMPubKeyLen=", parcel.MyTCMPubKeyLen)
		//}
		node.Init()
		node.SetConfig(parcel)
		nodes = append(nodes, node)
	}
	if len(nodes) == 1 {
		// 如果只有一个节点 不需要进行共识
		fmt.Println("node 0 start")
		// 启动该节点
		nodes[0].Start()
	} else {
		//初始化并启动节点
		for i := 0; i < len(nodes); i++ {
			go nodes[i].Start()
			fmt.Println("node", i, "start")
		}
		// 阻塞
		select {}
	}
}

var (
	file          string //配置文件路径
	dropDatabase  bool   //是否清空数据库
	tcmSupport    bool   //是否开启tcm模块
	tcmIndex      int    //tcm密钥序号
	tcmInterval   int    //tcm区块验证间隔
	sendMsgToMgmt bool   //是否向前端发送状态信息
	NumOfTCM      int    //tcm数量
)

func init() {
	flag.StringVar(&file, "f", "default", "config file")              //配置文件路径
	flag.BoolVar(&dropDatabase, "d", false, "delete database")        //是否清空数据库
	flag.BoolVar(&sendMsgToMgmt, "s", true, "send msg to management") //是否向前端发送状态信息
	flag.IntVar(&NumOfTCM, "n", 0, "num of tcm")                      //tcm数量
	flag.BoolVar(&tcmSupport, "tcm", false, "turn on tcm support")    //是否开启tcm模块
	flag.IntVar(&tcmIndex, "index", 5, "tcm index")                   //tcm密钥序号
	flag.IntVar(&tcmInterval, "interval", 20, "tcm verify interval")  //tcm区块验证间隔
}

func main() {
	flag.Parse()
	fmt.Println("欢迎使用PPoV区块链!")
	// common.CreateConfigFile()
	//utils.StartQRCodeServer()
	Run()
}
