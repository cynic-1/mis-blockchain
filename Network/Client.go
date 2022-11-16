package Network

import (
	network2 "MIS-BC/Network/network"
	"MIS-BC/Network/network/encoding"
	"MIS-BC/common"
	"MIS-BC/security/keymanager"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type ResponseforFE struct {
	Resp  []byte
	IsEnc bool
}

func SendResponse(conn net.Conn, data []byte, secretKey string) {
	fmt.Println("密钥为:", secretKey)
	if secretKey == "" {
		res, err := json.Marshal(ResponseforFE{Resp: data, IsEnc: false})
		if err != nil {
			fmt.Println("json.Marshal msg failed, err:", err)
			return
		}
		new_data, err := encoding.Encode(res)
		if err != nil {
			fmt.Println("encode msg failed, err:", err)
			return
		}
		_, err = conn.Write(new_data)
		if err != nil {
			fmt.Println(err)
		}
		return
	} else {
		new_data, _ := keymanager.SM4Encrypt(secretKey, data)
		//data:=base64.RawURLEncoding.EncodeToString(new_data)
		//new_data:=[]byte(Encypt.KeyEncrypt(secretKey,string(data)))
		res, err := json.Marshal(ResponseforFE{Resp: new_data, IsEnc: true})
		if err != nil {
			fmt.Println("json.Marshal msg failed, err:", err)
			return
		}
		msg, err := encoding.Encode(res)
		if err != nil {
			fmt.Println("encode msg failed, err:", err)
			return
		}
		_, err = conn.Write(msg)
		if err != nil {
			fmt.Println(err)
		}
		return
	}

}

func SendPacket(message []byte, ip string, port int) {
	port_s := strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", ip+":"+port_s, 3*time.Second)
	if err != nil {
		fmt.Println("dial failed, err", err)
		return
	}
	defer conn.Close()
	data, err := encoding.Encode(message)
	if err != nil {
		fmt.Println("encode msg failed, err:", err)
		return
	}
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("send msg failed, err:", err)
		return
	}

}

func SendPacketAndGetAns(message []byte, ip string, port int) []byte {
	port_s := strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", ip+":"+port_s, 3*time.Second)
	if err != nil {
		fmt.Println("dial failed, err", err)
		return nil
	}
	defer conn.Close()
	data, err := encoding.Encode(message)
	if err != nil {
		fmt.Println("encode msg failed, err:", err)
		return nil
	}
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("send msg failed, err:", err)
		return nil
	}

	msg, err := encoding.Decode(conn)
	if err == io.EOF {
		fmt.Println("IO errror, err:", err)
		return nil
	}
	if err != nil {
		fmt.Println("decode msg failed, err:", err)
		return nil
	}
	return msg
}

func (network *Network) SendToAll(message []byte, method int) {
	network.Mutex.Lock()
	tmpList := network.NodeList
	for k, x := range tmpList {
		if method == MIN {
			// TODO: MIN通信预留
		} else {
			// SendPacket(message, x.IP, x.PORT)
			network.SendPacketWithSavedConn(message, x.IP, x.PORT, k)
		}
	}
	network.Mutex.Unlock()
}

func (network *Network) SendToNeighbor(message []byte, method int) {
	network.Mutex.Lock()
	tmpList := network.NodeList
	temp := network.MyNodeInfo.ID

	for k, x := range tmpList {
		if x.ID == temp {
			continue
		}
		if method == MIN {
			// TODO: MIN通信预留
		} else {
			// SendPacket(message, x.IP, x.PORT)
			network.SendPacketWithSavedConn(message, x.IP, x.PORT, k)

		}
	}
	network.Mutex.Unlock()
}

func (network *Network) SendToOne(message []byte, receiver NodeID, method int) {
	network.Mutex.Lock()
	ip := network.NodeList[receiver].IP
	port := network.NodeList[receiver].PORT

	if method == MIN {
		// TODO: MIN通信预留
	} else {
		// SendPacket(message, ip, port)
		network.SendPacketWithSavedConn(message, ip, port, receiver)
	}

	network.Mutex.Unlock()
}

func (network *Network) SendMessage(message []byte, receiver NodeID) {
	if receiver == 0 {
		network.SendToAll(message, IP)
	} else if receiver == 1 {
		network.SendToNeighbor(message, IP)
	} else {
		network.SendToOne(message, receiver, IP)
	}
}

func (network *Network) SendPacketWithSavedConn(message []byte, ip string, port int, receiver NodeID) {
	var conn net.Conn
	conn_m, ok := network.NodeConnList[receiver]
	if ok && conn_m != nil {
		conn = conn_m
	} else {
		var err error
		port_s := strconv.Itoa(port)
		conn, err = net.DialTimeout("tcp", ip+":"+port_s, 3*time.Second)
		if err != nil {
			//fmt.Println("dial failed, err", err)
			//go network.updateNodeStatus(ip, port , 0)
			return
		}
		network.NodeConnList[receiver] = conn
	}

	//go network.updateNodeStatus(ip, port , 1)
	data, err := encoding.Encode(message)
	if err != nil {
		fmt.Println("encode msg failed, err:", err)
		return
	}
	_, err = conn.Write(data)
	if err != nil {
		//fmt.Println("send msg failed, err:", err)
		delete(network.NodeConnList, receiver)
		network.SendPacketWithSavedConn(message, ip, port, receiver)
		return
	}
}

func (network *Network) GetVMSSSLConn() network2.Connect {
	var bcnet network2.TCPNet
	var key keymanager.KeyManager
	key.GenKeyPair()
	conn, err := bcnet.Dials("localhost:12345", "localhost:54321", &key, []byte("04e067d23d3fd3ba4ead731b78346cde1084a837760f234621e36a93632b6f6418d4d6b735cd0ee19a8707ceca12ee4ff8106196ad8122ab2c89a7e11ba00d35b7"))
	if err != nil {
		common.Logger.Error("dail error:", err.Error())
		return nil
	}

	return conn
}
