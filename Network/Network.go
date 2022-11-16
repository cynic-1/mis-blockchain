package Network

import (
	netforvpn "MIS-BC/Network/network"
	"MIS-BC/common"
	"fmt"
	"github.com/gin-gonic/gin"
	"hash/crc32"
	"minlib/logicface"
	"minlib/security"
	"net"
	"strconv"
	"strings"
	"sync"
)

type NodeID = uint64

type NodeInfo struct {
	IP          string
	PORT        int
	Prefix      string
	ID          NodeID
	HostName    string
	AreaName    string
	CountryName string
	Longitude   float64 //经度
	Latitude    float64 //纬度
}

const (
	IP  = 0
	MIN = 1
)

//implementation of set which saves space
type Void struct{}

type Network struct {
	MyNodeInfo NodeInfo
	NodeList   map[NodeID]NodeInfo

	CBforBC       func([]byte)
	CBforFrontEnd func([]byte, net.Conn)
	CBforVPNMGMT  func(connect netforvpn.Connect)
	CBforMIR      func(lf *logicface.LogicFace)
	CBforVPNFE    func(connect netforvpn.Connect)
	CBforCRS      func(rg *gin.RouterGroup)

	Blacklist map[NodeID]Void
	Mutex     *sync.RWMutex

	//// 加密通信
	ServicePortforFE       int
	SSLIP                  string
	ServicePortforVPN      string
	ServiceSSLPortforVPN   string
	ServicePortforVPNFE    string
	ServiceSSLPortforVPNFE string
	SSLPrikey              string // 通信私钥
	SSLPubkey              string // 通信公钥

	CertificateInquires string
	Keychain            *security.KeyChain

	ConnSliceBC  []net.Conn
	ConnSliceMIN []net.Conn
	NodeConnList map[NodeID]net.Conn
}

func IPToValue(strIP string) uint32 {
	var a [4]uint32
	temp := strings.Split(strIP, ".")
	for i, x := range temp {
		t, err := strconv.Atoi(x)
		if err != nil {
			fmt.Println(err)
		}
		a[i] = uint32(t)
	}
	var ret uint32 = (a[0] << 24) + (a[1] << 16) + (a[2] << 8) + a[3]
	return ret
}

func GetNodeId(ip string, port int, prefix string) NodeID {
	if prefix != "" {
		return NodeID(crc32.ChecksumIEEE([]byte(prefix)))
	} else {
		var id uint32 = IPToValue(ip)
		var nid NodeID = NodeID(id) << 32
		nid += NodeID(port)
		return nid
	}
}

func (network *Network) AddNodeToNodeList(NodeID uint64, IPAddr string, Port int) {
	var nodelist NodeInfo
	nodelist.IP = IPAddr
	nodelist.PORT = Port
	nodelist.ID = NodeID
	network.Mutex.Lock()
	network.NodeList[NodeID] = nodelist
	network.Mutex.Unlock()
}

func (network *Network) RemoveNodeToNodeList(NodeID uint64) {
	network.Mutex.Lock()
	delete(network.NodeList, NodeID)
	network.Mutex.Unlock()
}

func (network *Network) SetConfig(config common.Config) {
	if config.MyAddress.PubIP != "" {
		network.MyNodeInfo.IP = config.MyAddress.PubIP
	} else {
		network.MyNodeInfo.IP = config.MyAddress.IP
	}

	// index := strconv.Itoa(int(crc32.ChecksumIEEE([]byte(config.MyPubkey))))

	network.MyNodeInfo.PORT = config.MyAddress.Port
	network.MyNodeInfo.Prefix = config.MyAddress.Prefix
	network.MyNodeInfo.ID = GetNodeId(network.MyNodeInfo.IP, network.MyNodeInfo.PORT, network.MyNodeInfo.Prefix)
	network.MyNodeInfo.HostName = config.HostName
	network.MyNodeInfo.AreaName = config.AreaName
	network.MyNodeInfo.CountryName = config.CountryName
	network.MyNodeInfo.Longitude = config.Longitude
	network.MyNodeInfo.Latitude = config.Latitude

	network.ServicePortforFE = config.ServicePortforFE
	network.NodeList = make(map[NodeID]NodeInfo)

	network.SSLPrikey = config.SSLPrikey
	network.SSLPubkey = config.SSLPubkey

	network.SSLIP = config.SSLIP
	network.ServicePortforVPN = config.ServicePortforVPN
	network.ServiceSSLPortforVPN = config.ServiceSSLPortforVPN
	network.ServicePortforVPNFE = config.ServicePortforVPNFE
	network.ServiceSSLPortforVPNFE = config.ServiceSSLPortforVPNFE

	network.Keychain.InitialKeyChainByPath(config.SqlitePath + config.HostName + "/")
	network.CertificateInquires = config.CertQueryPrefixforMIR + "/" + config.HostName

	//key := km.KeyManager{}
	//key.InitFromPem(config.Key.BlockChain)
	//network.Net.key = &key
	//misConfig := common.ParseConfig("mis-bc.ini")
	//Key := km.KeyManager{}
	//Key.Init()
	//Key.SetPriKey(misConfig.SSLPrikey)
	//Key.SetPubkey(misConfig.SSLPubkey)
	//network.Net = &net.TCPNet{
	//	key:Key,
	//}
	for _, x := range config.WorkerList {
		temp := GetNodeId(x.IP, x.Port, x.Prefix)
		_, ok := network.NodeList[temp]
		if !ok {
			var nodelist NodeInfo
			nodelist.IP = x.IP
			nodelist.PORT = x.Port
			nodelist.Prefix = x.Prefix
			nodelist.ID = temp
			network.NodeList[temp] = nodelist
		}
	}
	for _, x := range config.WorkerCandidateList {
		temp := GetNodeId(x.IP, x.Port, x.Prefix)
		_, ok := network.NodeList[temp]
		if !ok {
			var nodelist NodeInfo
			nodelist.IP = x.IP
			nodelist.PORT = x.Port
			nodelist.Prefix = x.Prefix
			nodelist.ID = temp
			network.NodeList[temp] = nodelist
		}
	}
	for _, x := range config.VoterList {
		temp := GetNodeId(x.IP, x.Port, x.Prefix)
		_, ok := network.NodeList[temp]
		if !ok {
			var nodelist NodeInfo
			nodelist.IP = x.IP
			nodelist.PORT = x.Port
			nodelist.Prefix = x.Prefix
			nodelist.ID = temp
			network.NodeList[temp] = nodelist
		}
	}
}

func (network *Network) SetCB(cbforbc func([]byte), cbforfe func([]byte, net.Conn), cbforvpn func(connect netforvpn.Connect), cbformir func(lf *logicface.LogicFace), cbforvpnfe func(connect netforvpn.Connect), cbforcrs func(rg *gin.RouterGroup)) {
	network.CBforBC = cbforbc
	network.CBforFrontEnd = cbforfe
	network.CBforVPNMGMT = cbforvpn
	network.CBforMIR = cbformir
	network.CBforVPNFE = cbforvpnfe
	network.CBforCRS = cbforcrs
}
