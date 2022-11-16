/**
 * @Author: xzw
 * @Description:
 * @Version: 1.0.0
 * @Date: 2021/6/2 晚上9:00
 * @Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
 */

package Network

import (
	netforvpn "MIS-BC/Network/network"
	"MIS-BC/Network/network/encoding"
	"MIS-BC/common"
	km "MIS-BC/security/keymanager"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"minlib/component"
	"minlib/logicface"
	"net"
	"net/http"
	"strconv"
)

// for blockchain over ip
func (network *Network) HandleConnection(conn net.Conn) {
	//defer conn.Close()
	//// 从连接中解码消息 前四个字节指定大小 防止粘包
	//msg, err := encoding.Decode(conn)
	//if err == io.EOF {
	//	return
	//}
	//if err != nil {
	//	fmt.Println("decode msg failed, err:", err)
	//	return
	//}
	//network.CBforBC(msg)

	defer func() {
		conn.Close()
		network.deleteConn(conn)
	}()
	for {
		// 从连接中解码消息 前四个字节指定大小 防止粘包
		msg, err := encoding.Decode(conn)
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Println("decode msg failed, err:", err)
			return
		}
		network.CBforBC(msg)
	}
}

func (network *Network) Start() {
	// 监听本节点端口
	port := strconv.Itoa(network.MyNodeInfo.PORT)
	listener, err := net.Listen("tcp", "0.0.0.0"+":"+port)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer listener.Close()
	// 死循环
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		network.ConnSliceBC = append(network.ConnSliceBC, conn)
		// 开启协程单独处理请求
		go network.HandleConnection(conn)
	}
}

func (network *Network) StartFEServer() {
	//fmt.Println("start:",network.MyNodeInfo.ID)
	port := strconv.Itoa(network.ServicePortforFE)
	//listener, err := net.Listen("tcp", network.MyNodeInfo.IP+":"+port)
	listener, err := net.Listen("tcp", "0.0.0.0"+":"+port)

	if err != nil {
		log.Fatal(err)
		return
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go network.HandleFEConnection(conn)
	}
}

// for FE
func (network *Network) HandleFEConnection(conn net.Conn) {
	defer conn.Close()
	msg, err := encoding.Decode(conn)
	if err == io.EOF {
		return
	}
	if err != nil {
		fmt.Println("decode msg failed, err:", err)
		return
	}
	network.CBforFrontEnd(msg, conn)
}

func (network *Network) StartVPNMGMTServer() {
	key := km.KeyManager{}
	key.Init()
	key.SetPriKey(network.SSLPrikey)
	key.SetPubkey(network.SSLPubkey)

	if key.IsOnCurve() == false {
		common.Logger.Fatal("Server creates failed..., because the private key and public key don't match.")
	}

	net := netforvpn.TCPNet{}
	// 加密连接监听
	err := net.Listens(network.SSLIP+":"+network.ServicePortforVPN, network.SSLIP+":"+network.ServiceSSLPortforVPN, &key)
	if err != nil {
		common.Logger.Fatal("Server Listens failed...")
	}
	common.Logger.Info("The server start success....")

	for {
		// accept连接
		conn, err := net.AcceptTCP()
		if err != nil {
			common.Logger.Fatal("Error accepting", err.Error())
		}
		// 开启一个新协程 单独处理连接
		go network.HandleVPNMGMTConnection(conn)
	}
}

// for FE
func (network *Network) HandleVPNMGMTConnection(conn netforvpn.Connect) {
	network.CBforVPNMGMT(conn)
}

func (network *Network) StartMIRServer() {
	lf := logicface.LogicFace{}
	if err := lf.InitWithUnixSocket("/tmp/mir.sock"); err != nil {
		common.Logger.Error(err)
		return
	}

	identifier, err := component.CreateIdentifierByString(network.CertificateInquires)
	if err != nil {
		common.Logger.Error(err)
		return
	}

	//// 初始化 KeyChain
	//keyChain, err := keychain.CreateKeyChain()
	//if err != nil {
	//	common.Logger.Error(err)
	//}
	//if err := keyChain.InitialKeyChainByPath("/usr/local/.mir/identity/"); err != nil {
	//	common.Logger.Error(err)
	//}
	//identity := keyChain.GetIdentityByName("root")
	//if identity == nil {
	//	common.Logger.Error("Identity -> ", "root not exists")
	//}
	//if err := keyChain.SetCurrentIdentity(identity, "Pkusz112233"); err != nil {
	//	common.Logger.Error(err)
	//}
	lf.SetKeyChain(network.Keychain)

	if err = lf.RegisterIdentifier(identifier, -1); err != nil {
		common.Logger.Error(err)
		return
	}

	//for true {
	//packet, err := lf.ReceiveCPacket(-1)
	//if err != nil {
	//	common.Logger.Error(err)
	//}
	go network.HandleMIRConnection(&lf)
	// common.LogInfo(count)
	//dstIdentifier := cPacket.DstIdentifier()
	//cPacket.SetDstIdentifier(cPacket.SrcIdentifier())
	//cPacket.SetSrcIdentifier(dstIdentifier)
	//cPacket.SetValue([]byte("Hello buddy!"))
	//if err := lf.SendCPacket(cPacket); err != nil {
	//	common.LogFatal(err)
	//}
	//}
}

// for MIR
func (network *Network) HandleMIRConnection(lf *logicface.LogicFace) {
	network.CBforMIR(lf)
}

func (network *Network) StartVPNFEServer() {
	key := km.KeyManager{}
	key.Init()
	key.SetPriKey(network.SSLPrikey)
	key.SetPubkey(network.SSLPubkey)

	if key.IsOnCurve() == false {
		common.Logger.Fatal("Server creates failed..., because the private key and public key don't match.")
	}

	net := netforvpn.TCPNet{}
	// 加密连接监听
	err := net.Listens(network.SSLIP+":"+network.ServicePortforVPNFE, network.SSLIP+":"+network.ServiceSSLPortforVPNFE, &key)
	if err != nil {
		common.Logger.Fatal("Server Listens failed...")
	}
	common.Logger.Info("The server start success....")

	for {
		// accept连接
		conn, err := net.AcceptTCP()
		if err != nil {
			common.Logger.Fatal("Error accepting", err.Error())
		}
		// 开启一个新协程 单独处理连接
		go network.HandleVPNFEConnection(conn)
	}
}

// for VPNFE
func (network *Network) HandleVPNFEConnection(conn netforvpn.Connect) {
	network.CBforVPNFE(conn)
}

func (network *Network) StartCRSServer() {
	// 初始化 Gin 框架默认实例，该实例包含了路由、中间件以及配置信息
	r := gin.Default()

	r.Use(network.Cors()) //开启中间件 允许使用跨域请求

	v1 := r.Group("/api/v1/mis")
	network.HandleCRSConnection(v1)

	r.Run(":8080")
}

func (network *Network) HandleCRSConnection(rg *gin.RouterGroup) {
	network.CBforCRS(rg)
}

func (network *Network) deleteConn(conn net.Conn) error {
	if conn == nil {
		fmt.Println("conn is nil")
		return errors.New("conn is nil")
	}
	for i := 0; i < len(network.ConnSliceBC); i++ {
		if network.ConnSliceBC[i] == conn {
			network.ConnSliceBC = append(network.ConnSliceBC[:i], network.ConnSliceBC[i+1:]...)
			break
		}
	}
	return nil
}

func (network *Network) Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin") //请求头部
		if origin != "" {
			//接收客户端发送的origin （重要！）
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			//服务器支持的所有跨域请求的方法
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE")
			//允许跨域设置可以返回其他子段，可以自定义字段
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session")
			// 允许浏览器（客户端）可以解析的头部 （重要）
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers")
			//设置缓存时间
			c.Header("Access-Control-Max-Age", "172800")
			//允许客户端传递校验信息比如 cookie (重要)
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		//允许类型校验
		if method == "OPTIONS" {
			c.JSON(http.StatusOK, "ok!")
		}

		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic info is: %v", err)
			}
		}()

		c.Next()
	}
}

//func (network *Network) Start() {
//	// 监听本节点端口
//	port := strconv.Itoa(network.MyNodeInfo.PORT)
//	listener, err := net.Listen("tcp", "0.0.0.0"+":"+port)
//	if err != nil {
//		log.Fatal(err)
//		return
//	}
//	defer listener.Close()
//	// 死循环
//	for {
//		conn, err := listener.Accept()
//		if err != nil {
//			log.Println(err)
//			continue
//		}
//		// 开启协程单独处理请求
//		go network.HandleConnection(conn)
//	}
//
//	//key := km.KeyManager{}
//	//key.InitFromPem(network.KeyPath)
//	//network.Net.Listens(port, "12345", &key)
//	// listener, err := net.Listen("tcp", "0.0.0.0"+":"+port)
//	//if err != nil {
//	//	log.Fatal(err)
//	//	return
//	//}
//	//defer listener.Close()
//	// 死循环
//	//for {
//	//	conn, err := network.Net.Accept()
//	//	if err != nil {
//	//		fmt.Println("Error accepting", err.Error())
//	//		continue
//	//	}
//	//	// 开启协程单独处理请求
//	//	go network.HandleConnection(conn)
//	//}
//}
//
//// for blockchain over ip
//func (network *Network) HandleConnection(conn net.Conn) {
//	defer conn.Close()
//	// 从连接中解码消息 前四个字节指定大小 防止粘包
//	msg, err := encoding.Decode(conn)
//	if err == io.EOF {
//		return
//	}
//	if err != nil {
//		fmt.Println("decode msg failed, err:", err)
//		return
//	}
//	network.CBforBC(msg)
//	//defer conn.Close()
//	//// 从连接中解码消息 前四个字节指定大小 防止粘包
//	//msg, err := conn.Read()
//	//if err != nil {
//	//	fmt.Println("Error Reading", err.Error())
//	//	return // 终止程序
//	//}
//	//network.CBforBC(msg)
//}
//
//func (network *Network) StartFEServer() {
//	//fmt.Println("start:",network.MyNodeInfo.ID)
//	port := strconv.Itoa(network.ServicePortforFE)
//	//listener, err := net.Listen("tcp", network.MyNodeInfo.IP+":"+port)
//	key := km.KeyManager{}
//	key.Init()
//	key.SetPriKey(network.SSLPrikey)
//	key.SetPubkey(network.SSLPubkey)
//	if key.IsOnCurve() == false {
//		common.Logger.Fatal("Server creates failed..., because the private key and public key don't match.")
//	}
//
//	net := nt.TCPNet{}
//	err := net.Listens(network.MyNodeInfo.IP+":"+port, network.SSLIP+":"+strconv.Itoa(network.SSLPort), &key)
//
//	// listener, err := net.Listen("tcp", "0.0.0.0"+":"+port)
//	if err != nil {
//		common.Logger.Fatal("Server Listens failed...")
//	}
//	//if err != nil {
//	//	log.Fatal(err)
//	//	return
//	//}
//	// defer listener.Close()
//	common.Logger.Info("The server start success....")
//	for {
//		conn, err := net.Accept()
//		if err != nil {
//			common.Logger.Fatal("Error accepting", err.Error())
//		}
//		// 开启协程单独处理请求
//		go network.HandleFEConnection(conn)
//	}
//}
//
//// for MIN
//func (network *Network) HandleFEConnection(conn nt.Connect) {
//	defer conn.Close()
//	msg, err := conn.Read()
//	//if err == io.EOF {
//	//	return
//	//}
//	if err != nil {
//		fmt.Println("Error Reading", err.Error())
//		return // 终止程序
//	}
//	network.CBforFrontEnd(msg, conn)
//}
