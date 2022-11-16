/**
 * @Author: xzw
 * @Description:
 * @Version: 1.0.0
 * @Date: 2021/6/3 下午5:00
 * @Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
 */
package common

import (
	"MIS-BC/security/keymanager"
	"fmt"
	"gopkg.in/ini.v1"
	"log"
	"strconv"
	"strings"
)

// AddressPair 地址信息结构体
type AddressPair struct {
	IP     string // 地址IP
	PubIP  string // 公网或第一跳IP
	Port   int    // 地址端口号
	Prefix string // 地址前缀，在MIN通信时候用到
}

// AreaPair 地址信息结构体
type AreaPair struct {
	HostName    string  // 主机名
	AreaName    string  // 地区名
	CountryName string  // 国家名
	Longitude   float64 // 经度
	Latitude    float64 // 纬度
}

// Config 配置文件对象 读取配置文件内容并更新其中变量
type Config struct {
	// 日志配置信息
	LogToFile bool   //是否记录到日志文件中
	LogPath   string //日志文件路径
	Level     int
	StartTime string //日志统计开始的时间点

	// 区块链节点信息
	WorkerList             []AddressPair //记账节点地址信息列表
	WorkerCandidateList    []AddressPair //候选记账节点信息列表
	VoterList              []AddressPair //投票节点信息列表
	BCManagementServerList []AddressPair //区块链管理后台IP

	MyAddress AddressPair //本节点地址信息
	//IdentityIdentifier  string		  //身份标识

	PubkeyList          []string //公钥列表
	PrikeyList          []string //私钥列表
	SingleServerNodeNum int      //单台服务器运行节点数量
	MyPubkey            string   //本节点公钥
	MyPrikey            string   //本节点私钥

	GenesisDutyWorker   int     //代理记账节点
	WorkerNum           int     //记账节点数量
	VotedNum            int     //记账节点数量投票节点数量
	ServerNum           int     //BC管理服务器数量
	IsMINConn           bool    //是否基于MIN通信
	TxPoolSize          int     //交易池大小
	BlockGroupPerCycle  int     //每个共识周期产生的区块组数量
	Tcut                float64 //每轮共识时间
	GenerateBlockPeriod float64 //生成区块周期
	DropDatabase        bool    //是否清空数据库
	SendMsgToBCMgmt     bool    //是否向区块链管理后台发送状态信息

	CountryName string  //国家名
	AreaName    string  //地区名
	HostName    string  //节点名
	Longitude   float64 //经度
	Latitude    float64 //纬度
	CacheTime   int     //缓存多长的时间的区块链状态记录,单位为分钟

	// TCM可信计算
	TCMSupport     bool      //是否开启可信计算
	TCMIndex       uint32    //tcm序列号
	TCMInterval    int       //tcm验证周期
	NumOfTCM       int       //tcm数量
	MyTCMPubKey    [65]uint8 //本节点tcm公钥
	MyTCMPubKeyLen uint32    //本节点tcm公钥长度

	// 管理域
	IsNewJoin          int  //是否是新加入的节点
	OpenOtherNodeServe bool //本地有多个节点确定从节点是否向前端VMS等开启监听端口
	OpenRPCServe       bool //是否开启RPC注册服务

	// 加密通信
	ServicePortforFE int // 提供给前端的通信端口

	SSLPrikey string // 通信私钥
	SSLPubkey string // 通信公钥

	SSLIP                string // 监听IP
	ServicePortforVPN    string // 提供给VPN管理后台的端口
	ServiceSSLPortforVPN string

	ServicePortforVPNFE    string // 提供给VPN前端的端口
	ServiceSSLPortforVPNFE string

	DefaultExpiration int // 默认有效期
	CleanupInterval   int // 清理周期

	CertQueryPrefixforMIR string
	CertRespondforMIR     string

	SqlitePath string

	SecretID  string
	SecretKey string

	AppId     string
	AppSecret string
}

func CreateConfigFile() {
	var conf Config
	conf.IsMINConn = true           // 是否与MIR进行通信
	conf.LogToFile = false          // 是否将日志输出到日志文件中
	conf.LogPath = "./logs/log.log" // 日志文件的路径
	conf.StartTime = "1642125461000"
	var servers = []AddressPair{ // 区块链服务器
		{
			IP:    "121.15.171.86", // 私网IP地址（没有可空）
			PubIP: "121.15.171.86", // 公网IP地址（没有可空）
			Port:  5010,            // 区块链使用的端口号，建议统一使用5010
		},
		{
			IP:    "121.15.171.84",
			PubIP: "121.15.171.84",
			Port:  5010,
		},
		{
			IP:    "121.15.171.85",
			PubIP: "121.15.171.85",
			Port:  5010,
		},
		{
			IP:    "121.15.171.90",
			PubIP: "121.15.171.90",
			Port:  5010,
		},
		{
			IP:    "121.15.171.91",
			PubIP: "121.15.171.91",
			Port:  5010,
		},
	}
	conf.SingleServerNodeNum = 1 // 每台服务器跑1个区块链节点
	for i := 0; i < len(servers); i++ {
		for j := 0; j < conf.SingleServerNodeNum; j++ {
			var addr = AddressPair{
				IP:   servers[i].IP,
				Port: servers[i].Port + j,
			}
			conf.WorkerList = append(conf.WorkerList, addr)
			conf.WorkerCandidateList = append(conf.WorkerCandidateList, addr)
			conf.VoterList = append(conf.VoterList, addr)
			conf.BCManagementServerList = append(conf.BCManagementServerList, addr)
		}
	}
	conf.GenesisDutyWorker = 0
	conf.WorkerNum = 5               // 记账节点数
	conf.VotedNum = 5                // 投票节点数
	conf.ServerNum = 5               // 运行区块链管理程序的节点数
	conf.BlockGroupPerCycle = 100000 // 记账节点轮换周期
	conf.Tcut = 20                   // 超时时间
	conf.GenerateBlockPeriod = 4     // 产生区块周期
	conf.TxPoolSize = 100000         // 交易池大小

	conf.IsNewJoin = 0              // 是否新加入的节点
	conf.OpenOtherNodeServe = false //不开从节点的多余端口
	conf.OpenRPCServe = false       //不开RPC注册服务

	conf.ServicePortforFE = 8010 // 提供给前端的通信接口
	conf.SSLPrikey = "c907424efdce6903ff380a351d7f2cce3ff06d58512792873abd090bf1c9a84b"
	conf.SSLPubkey = "04e067d23d3fd3ba4ead731b78346cde1084a837760f234621e36a93632b6f6418d4d6b735cd0ee19a8707ceca12ee4ff8106196ad8122ab2c89a7e11ba00d35b7"
	conf.SSLIP = "0.0.0.0"
	conf.ServicePortforVPN = "9999"    // 提供给VMS的连接接口
	conf.ServiceSSLPortforVPN = "6666" // 提供给VMS的通信接口
	conf.ServicePortforVPNFE = "8888"
	conf.ServiceSSLPortforVPNFE = "7777"

	conf.DefaultExpiration = 10 // Session默认有效期，单位为分钟
	conf.CleanupInterval = 10   // Session清理周期，单位为分钟

	conf.SqlitePath = "/home/min/identity/"  // sqlite数据库文件地址
	conf.CertRespondforMIR = "/mir/cert"     // MIR查询证书信息的前缀
	conf.CertQueryPrefixforMIR = "/mis/cert" // 返回证书查询结果的前缀

	conf.SecretID = "AKIDpUs0qQjlVyB7mAH7gz2KM6ZlfIfla7NN"
	conf.SecretKey = "kDPJxKQFo55oGRKwGK7drpWw5xYsufAN"

	conf.AppId = "wx8353d0a14c2c99fe"
	conf.AppSecret = "1f4bf3af036e2ebc684b292358e4368b"

	var area = []AreaPair{ // 区块链服务器的地理位置信息
		{
			HostName:    "node9",    // 节点名称
			AreaName:    "Shenzhen", // 节点所在地区名
			CountryName: "China",    // 节点所在国家名
			Longitude:   114.07,     // 节点所在经度
			Latitude:    22.62,      // 节点所在纬度
		},
		{
			HostName:    "node11",
			AreaName:    "Shenzhen", // 节点所在地区名
			CountryName: "China",    // 节点所在国家名
			Longitude:   114.07,     // 节点所在经度
			Latitude:    22.62,      // 节点所在纬度
		},
		{
			HostName:    "node14",
			AreaName:    "Shenzhen", // 节点所在地区名
			CountryName: "China",    // 节点所在国家名
			Longitude:   114.07,     // 节点所在经度
			Latitude:    22.62,      // 节点所在纬度
		},
		{
			HostName:    "gdcni18",
			AreaName:    "Shenzhen", // 节点所在地区名
			CountryName: "China",    // 节点所在国家名
			Longitude:   114.07,     // 节点所在经度
			Latitude:    22.62,      // 节点所在纬度
		},
		{
			HostName:    "gdcni16",
			AreaName:    "Shenzhen", // 节点所在地区名
			CountryName: "China",    // 节点所在国家名
			Longitude:   114.07,     // 节点所在经度
			Latitude:    22.62,      // 节点所在纬度
		},
	}
	conf.CacheTime = 10 // 缓存节点状态信息的时长，单位为分钟

	//对每个服务器进行特定化配置
	for i := 0; i < len(servers); i++ {
		var config = conf
		config.MyAddress = servers[i]
		config.ServicePortforFE = conf.ServicePortforFE //change in need
		config.HostName = area[i].HostName
		config.AreaName = area[i].AreaName
		config.AreaName = area[i].CountryName
		config.Longitude = area[i].Longitude
		config.Latitude = area[i].Latitude
		var config_name = "config_" + servers[i].IP + "_" + strconv.Itoa(servers[i].Port) + "_" + strconv.Itoa(config.SingleServerNodeNum)
		for i := 0; i < config.SingleServerNodeNum; i++ {
			var keyManager keymanager.KeyManager
			keyManager.Init()
			keyManager.GenKeyPair()
			config.PubkeyList = append(config.PubkeyList, keyManager.GetPubkey())
			config.PrikeyList = append(config.PrikeyList, keyManager.GetPriKey())
		}
		config.WriteFile(config_name)
		fmt.Println(config)
	}
}

func CreateLocalConfigFile() {
	var conf Config
	conf.IsMINConn = false
	conf.LogToFile = false
	conf.LogPath = "./logs/log.log"
	conf.Level = 6
	conf.StartTime = "1642125461000"

	var servers = []AddressPair{
		{
			IP:    "127.0.0.1",
			PubIP: "",
			Port:  5010,
		},
	}

	conf.HostName = "本地"
	conf.AreaName = "Shenzhen"
	conf.CountryName = "China"
	conf.Longitude = 114.06667
	conf.Latitude = 22.61667
	conf.CacheTime = 10

	conf.SingleServerNodeNum = 5
	//var total_nodes=conf.SingleServerNodeNum* len(servers)
	for i := 0; i < len(servers); i++ {
		for j := 0; j < conf.SingleServerNodeNum; j++ {
			var addr = AddressPair{
				IP:     servers[i].IP,
				Port:   servers[i].Port + j,
				Prefix: servers[i].Prefix,
			}
			conf.WorkerList = append(conf.WorkerList, addr)
			conf.WorkerCandidateList = append(conf.WorkerCandidateList, addr)
			conf.VoterList = append(conf.VoterList, addr)
			conf.BCManagementServerList = append(conf.BCManagementServerList, addr)
		}
	}
	conf.GenesisDutyWorker = 0
	conf.WorkerNum = 5
	conf.VotedNum = 5
	conf.ServerNum = 1
	conf.BlockGroupPerCycle = 100000
	conf.Tcut = 20
	conf.GenerateBlockPeriod = 8
	conf.TxPoolSize = 100000

	conf.IsNewJoin = 0
	conf.OpenOtherNodeServe = false //不开从节点的多余端口
	conf.OpenRPCServe = false       //不开RPC注册服务

	conf.ServicePortforFE = 8010
	conf.SSLPrikey = "c907424efdce6903ff380a351d7f2cce3ff06d58512792873abd090bf1c9a84b"
	conf.SSLPubkey = "04e067d23d3fd3ba4ead731b78346cde1084a837760f234621e36a93632b6f6418d4d6b735cd0ee19a8707ceca12ee4ff8106196ad8122ab2c89a7e11ba00d35b7"
	conf.SSLIP = "0.0.0.0"
	conf.ServicePortforVPN = "9999"
	conf.ServiceSSLPortforVPN = "6666"
	conf.ServicePortforVPNFE = "8888"
	conf.ServiceSSLPortforVPNFE = "7777"

	conf.DefaultExpiration = 1000
	conf.CleanupInterval = 10

	conf.SqlitePath = "/home/min/identity/"
	conf.CertRespondforMIR = "/mir/cert"
	conf.CertQueryPrefixforMIR = "/mis/cert"

	conf.SecretID = "AKIDpUs0qQjlVyB7mAH7gz2KM6ZlfIfla7NN"
	conf.SecretKey = "kDPJxKQFo55oGRKwGK7drpWw5xYsufAN"

	conf.AppId = "wx8353d0a14c2c99fe"
	conf.AppSecret = "1f4bf3af036e2ebc684b292358e4368b"

	//对每个服务器进行特定化配置
	for i := 0; i < len(servers); i++ {
		var config = conf
		config.MyAddress = servers[i]
		config.ServicePortforFE = conf.ServicePortforFE //change in need
		var config_name = "config_" + servers[i].IP + "_" + strconv.Itoa(servers[i].Port) + "_" + strconv.Itoa(config.SingleServerNodeNum)
		for i := 0; i < config.SingleServerNodeNum; i++ {
			var keyManager keymanager.KeyManager
			keyManager.Init()
			keyManager.GenKeyPair()
			config.PubkeyList = append(config.PubkeyList, keyManager.GetPubkey())
			config.PrikeyList = append(config.PrikeyList, keyManager.GetPriKey())
		}
		config.WriteFile(config_name)
		fmt.Println(config)
	}
}

func (conf Config) WriteFile(file string) {
	c := ini.Empty()

	LogSection, err := c.NewSection("Log")
	if err != nil {
		log.Fatal("new Log Section failed:", err)
	}
	LogSection.NewKey("LogToFile", strconv.FormatBool(conf.LogToFile))
	LogSection.NewKey("LogPath", conf.LogPath)
	LogSection.NewKey("Level", strconv.Itoa(conf.Level))
	LogSection.NewKey("StartTime", conf.StartTime)
	NodeSection, err := c.NewSection("Node")
	if err != nil {
		log.Fatal("new Network Section failed:", err)
	}

	//设置WorkList
	str := ""
	for i := 0; i < len(conf.WorkerList); i++ {
		//if conf.IsMINConn {
		//	str += conf.WorkerList[i].Prefix
		//} else {
		//	str += conf.WorkerList[i].IP + ":" + strconv.Itoa(conf.WorkerList[i].Port)
		//}
		str += conf.WorkerList[i].IP + ":" + strconv.Itoa(conf.WorkerList[i].Port)
		if i != len(conf.WorkerList)-1 {
			str += ","
		}
	}
	NodeSection.NewKey("WorkerList", str)

	//设置WorkerCandidateList
	str = ""
	for i := 0; i < len(conf.WorkerCandidateList); i++ {
		//if conf.IsMINConn {
		//	str += conf.WorkerCandidateList[i].Prefix
		//} else {
		//	str += conf.WorkerCandidateList[i].IP + ":" + strconv.Itoa(conf.WorkerCandidateList[i].Port)
		//}
		str += conf.WorkerCandidateList[i].IP + ":" + strconv.Itoa(conf.WorkerCandidateList[i].Port)
		if i != len(conf.WorkerCandidateList)-1 {
			str += ","
		}
	}
	NodeSection.NewKey("WorkerCandidateList", str)
	//设置VoterList
	str = ""
	for i := 0; i < len(conf.VoterList); i++ {
		//if conf.IsMINConn {
		//	str += conf.VoterList[i].Prefix
		//} else {
		//	str += conf.VoterList[i].IP + ":" + strconv.Itoa(conf.VoterList[i].Port)
		//}
		str += conf.VoterList[i].IP + ":" + strconv.Itoa(conf.VoterList[i].Port)
		if i != len(conf.VoterList)-1 {
			str += ","
		}
	}
	NodeSection.NewKey("VoterList", str)

	//设置BCManagementServerList
	str = ""
	for i := 0; i < len(conf.BCManagementServerList); i++ {
		str += conf.BCManagementServerList[i].IP + ":" + strconv.Itoa(conf.BCManagementServerList[i].Port)
		if i != len(conf.BCManagementServerList)-1 {
			str += ","
		}
	}
	NodeSection.NewKey("BCManagementServerList", str)
	NodeSection.NewKey("ServerNum", strconv.Itoa(conf.ServerNum))

	//设置SingleServerNodeNum
	NodeSection.NewKey("SingleServerNodeNum", strconv.Itoa(conf.SingleServerNodeNum))
	//设置IP
	NodeSection.NewKey("IdentityIdentifier", conf.MyAddress.Prefix)
	NodeSection.NewKey("IP", conf.MyAddress.IP)
	NodeSection.NewKey("PubIP", conf.MyAddress.PubIP)
	NodeSection.NewKey("Port", strconv.Itoa(conf.MyAddress.Port))

	NodeSection.NewKey("HostName", conf.HostName)
	NodeSection.NewKey("AreaName", conf.AreaName)
	NodeSection.NewKey("CountryName", conf.CountryName)
	NodeSection.NewKey("Longitude", strconv.FormatFloat(conf.Longitude, 'f', 2, 64))
	NodeSection.NewKey("Latitude", strconv.FormatFloat(conf.Latitude, 'f', 2, 64))
	NodeSection.NewKey("CacheTime", strconv.Itoa(conf.CacheTime))

	NodeSection.NewKey("IsNewJoin", strconv.Itoa(conf.IsNewJoin))
	NodeSection.NewKey("IsMINConn", strconv.FormatBool(conf.IsMINConn))
	NodeSection.NewKey("OpenOtherNodeServe", strconv.FormatBool(conf.OpenOtherNodeServe))
	NodeSection.NewKey("OpenRPCServe", strconv.FormatBool(conf.OpenRPCServe))

	pubkey := ""
	prikey := ""
	for i := 0; i < conf.SingleServerNodeNum; i++ {
		pubkey += conf.PubkeyList[i]
		if i != conf.SingleServerNodeNum-1 {
			pubkey += ","
		}
		prikey += conf.PrikeyList[i]
		if i != conf.SingleServerNodeNum-1 {
			prikey += ","
		}
	}

	ConsensusSection, err := c.NewSection("Consensus")
	if err != nil {
		log.Fatal("new ConsensusSection Section failed:", err)
	}
	ConsensusSection.NewKey("PubkeyList", pubkey)
	ConsensusSection.NewKey("PrikeyList", prikey)
	ConsensusSection.NewKey("MyPubkey", conf.MyPubkey)
	ConsensusSection.NewKey("MyPrikey", conf.MyPrikey)
	ConsensusSection.NewKey("GenesisDutyWorker", strconv.Itoa(conf.GenesisDutyWorker))
	ConsensusSection.NewKey("WorkerNum", strconv.Itoa(conf.WorkerNum))
	ConsensusSection.NewKey("VotedNum", strconv.Itoa(conf.VotedNum))
	ConsensusSection.NewKey("BlockGroupPerCycle", strconv.Itoa(conf.BlockGroupPerCycle))
	ConsensusSection.NewKey("Tcut", strconv.FormatFloat(conf.Tcut, 'f', 2, 64))
	ConsensusSection.NewKey("GenerateBlockPeriod", strconv.FormatFloat(conf.GenerateBlockPeriod, 'f', 2, 64))
	ConsensusSection.NewKey("TxPoolSize", strconv.Itoa(conf.TxPoolSize))

	SSLSection, err := c.NewSection("SSL")
	SSLSection.NewKey("ServicePortforFE", strconv.Itoa(conf.ServicePortforFE))
	SSLSection.NewKey("SSLPrikey", conf.SSLPrikey)
	SSLSection.NewKey("SSLPubkey", conf.SSLPubkey)
	SSLSection.NewKey("SSLIP", conf.SSLIP)
	SSLSection.NewKey("ServicePortforVPN", conf.ServicePortforVPN)
	SSLSection.NewKey("ServiceSSLPortforVPN", conf.ServiceSSLPortforVPN)
	SSLSection.NewKey("ServicePortforVPNFE", conf.ServicePortforVPNFE)
	SSLSection.NewKey("ServiceSSLPortforVPNFE", conf.ServiceSSLPortforVPNFE)

	SESSIONSection, err := c.NewSection("SESSION")
	SESSIONSection.NewKey("DefaultExpiration", strconv.Itoa(conf.DefaultExpiration))
	SESSIONSection.NewKey("CleanupInterval", strconv.Itoa(conf.CleanupInterval))

	MIRSection, err := c.NewSection("MIR")
	MIRSection.NewKey("SqlitePath", conf.SqlitePath)
	MIRSection.NewKey("CertQueryPrefixforMIR", conf.CertQueryPrefixforMIR)
	MIRSection.NewKey("CertRespondforMIR", conf.CertRespondforMIR)

	SMSSection, err := c.NewSection("SMS")
	SMSSection.NewKey("SecretID", conf.SecretID)
	SMSSection.NewKey("SecretKey", conf.SecretKey)

	QRSection, err := c.NewSection("QR")
	QRSection.NewKey("AppId", conf.AppId)
	QRSection.NewKey("AppSecret", conf.AppSecret)

	err = c.SaveTo(file)
	if err != nil {
		Logger.Fatal("SaveTo failed: ", err)
	}
}

func ParseConfig(path string) Config {
	cfg, err := ini.Load(path)
	if err != nil {
		Logger.Fatal("Fail to read ini file:", err)
	}
	Conf := Config{}
	Conf.Init(cfg)
	return Conf
}

func (conf *Config) Init(c *ini.File) {
	var err error
	// 初始化日志配置
	conf.LogToFile, err = c.Section("Log").Key("LogToFile").Bool()
	conf.LogPath = c.Section("Log").Key("LogPath").String()
	conf.Level, err = c.Section("Log").Key("Level").Int()
	conf.StartTime = c.Section("Log").Key("StartTime").String()

	//读取SingleServerNodeNum
	conf.SingleServerNodeNum, _ = c.Section("Node").Key("SingleServerNodeNum").Int()
	//读取IP、端口
	conf.MyAddress.IP = c.Section("Node").Key("IP").String()
	conf.MyAddress.PubIP = c.Section("Node").Key("PubIP").String()
	conf.MyAddress.Port, _ = c.Section("Node").Key("Port").Int()
	conf.MyAddress.Prefix = c.Section("Node").Key("IdentityIdentifier").String()
	conf.ServerNum, err = c.Section("Node").Key("ServerNum").Int()
	conf.IsNewJoin, err = c.Section("Node").Key("IsNewJoin").Int()
	conf.IsMINConn, err = c.Section("Node").Key("IsMINConn").Bool()
	conf.OpenOtherNodeServe, err = c.Section("Node").Key("OpenOtherNodeServe").Bool()
	conf.OpenRPCServe, err = c.Section("Node").Key("OpenRPCServe").Bool()

	conf.HostName = c.Section("Node").Key("HostName").String()
	conf.AreaName = c.Section("Node").Key("AreaName").String()
	conf.CountryName = c.Section("Node").Key("CountryName").String()
	longitude := c.Section("Node").Key("Longitude").String()
	latitude := c.Section("Node").Key("Latitude").String()
	conf.Longitude, err = strconv.ParseFloat(longitude, 64)
	conf.Latitude, err = strconv.ParseFloat(latitude, 64)
	conf.CacheTime, err = c.Section("Node").Key("CacheTime").Int()

	conf.MyPubkey = c.Section("Consensus").Key("MyPubkey").String()
	conf.MyPrikey = c.Section("Consensus").Key("MyPrikey").String()
	conf.GenesisDutyWorker, err = c.Section("Consensus").Key("GenesisDutyWorker").Int()
	conf.WorkerNum, err = c.Section("Consensus").Key("WorkerNum").Int()
	conf.VotedNum, err = c.Section("Consensus").Key("VotedNum").Int()
	conf.BlockGroupPerCycle, err = c.Section("Consensus").Key("BlockGroupPerCycle").Int()
	tcut := c.Section("Consensus").Key("Tcut").String()
	GenerateBlockPeriod := c.Section("Consensus").Key("GenerateBlockPeriod").String()
	conf.TxPoolSize, err = c.Section("Consensus").Key("TxPoolSize").Int()

	conf.Tcut, err = strconv.ParseFloat(tcut, 64)
	conf.GenerateBlockPeriod, err = strconv.ParseFloat(GenerateBlockPeriod, 64)

	//读取WorkerList
	str := c.Section("Node").Key("WorkerList").String()
	str_nodes := strings.Split(str, ",")
	conf.WorkerList = []AddressPair{}
	for _, str_node := range str_nodes {
		var addr AddressPair
		//if conf.IsMINConn {
		//	addr.Prefix = str_node
		//} else {
		//	split_str_node := strings.Split(str_node, ":")
		//	addr.IP = split_str_node[0]
		//	addr.Port, _ = strconv.Atoi(split_str_node[1])
		//}
		split_str_node := strings.Split(str_node, ":")
		addr.IP = split_str_node[0]
		addr.Port, _ = strconv.Atoi(split_str_node[1])
		conf.WorkerList = append(conf.WorkerList, addr)
	}

	//读取WorkerCandidateList
	str = c.Section("Node").Key("WorkerCandidateList").String()
	str_nodes = strings.Split(str, ",")
	conf.WorkerCandidateList = []AddressPair{}
	for _, str_node := range str_nodes {
		var addr AddressPair
		//if conf.IsMINConn {
		//	addr.Prefix = str_node
		//} else {
		//	split_str_node := strings.Split(str_node, ":")
		//	addr.IP = split_str_node[0]
		//	addr.Port, _ = strconv.Atoi(split_str_node[1])
		//}
		split_str_node := strings.Split(str_node, ":")
		addr.IP = split_str_node[0]
		addr.Port, _ = strconv.Atoi(split_str_node[1])
		conf.WorkerCandidateList = append(conf.WorkerCandidateList, addr)
	}

	//读取VoterList
	str = c.Section("Node").Key("VoterList").String()
	str_nodes = strings.Split(str, ",")
	conf.VoterList = []AddressPair{}
	for _, str_node := range str_nodes {
		var addr AddressPair
		split_str_node := strings.Split(str_node, ":")
		addr.IP = split_str_node[0]
		addr.Port, _ = strconv.Atoi(split_str_node[1])
		conf.VoterList = append(conf.VoterList, addr)
	}

	//读取ManagementServerList
	str = c.Section("Node").Key("BCManagementServerList").String()
	str_nodes = strings.Split(str, ",")
	conf.BCManagementServerList = []AddressPair{}
	for _, str_node := range str_nodes {
		var addr AddressPair
		split_str_node := strings.Split(str_node, ":")
		addr.IP = split_str_node[0]
		addr.Port, _ = strconv.Atoi(split_str_node[1])
		conf.BCManagementServerList = append(conf.BCManagementServerList, addr)
	}

	//读取公私钥列表
	pubkeys := c.Section("Consensus").Key("PubkeyList").String()
	prikeys := c.Section("Consensus").Key("PrikeyList").String()
	for i := 0; i < conf.SingleServerNodeNum; i++ {
		conf.PubkeyList = strings.Split(pubkeys, ",")
		conf.PrikeyList = strings.Split(prikeys, ",")
	}

	conf.ServicePortforFE, err = c.Section("SSL").Key("ServicePortforFE").Int()
	conf.SSLPrikey = c.Section("SSL").Key("SSLPrikey").String()
	conf.SSLPubkey = c.Section("SSL").Key("SSLPubkey").String()
	conf.SSLIP = c.Section("SSL").Key("SSLIP").String()
	conf.ServicePortforVPN = c.Section("SSL").Key("ServicePortforVPN").String()
	conf.ServiceSSLPortforVPN = c.Section("SSL").Key("ServiceSSLPortforVPN").String()
	conf.ServicePortforVPNFE = c.Section("SSL").Key("ServicePortforVPNFE").String()
	conf.ServiceSSLPortforVPNFE = c.Section("SSL").Key("ServiceSSLPortforVPNFE").String()

	conf.SqlitePath = c.Section("MIR").Key("SqlitePath").String()
	conf.CertQueryPrefixforMIR = c.Section("MIR").Key("CertQueryPrefixforMIR").String()
	conf.CertRespondforMIR = c.Section("MIR").Key("CertRespondforMIR").String()

	conf.DefaultExpiration, err = c.Section("SESSION").Key("DefaultExpiration").Int()
	conf.CleanupInterval, err = c.Section("SESSION").Key("CleanupInterval").Int()
	// conf.Key.MINVPN = c.Section("Key").Key("MIN-VPN").String()

	conf.SecretID = c.Section("SMS").Key("SecretID").String()
	conf.SecretKey = c.Section("SMS").Key("SecretKey").String()

	conf.AppId = c.Section("QR").Key("AppId").String()
	conf.AppSecret = c.Section("QR").Key("AppSecret").String()

	if err != nil {
		log.Fatal("Please check the config file")
	}
}
