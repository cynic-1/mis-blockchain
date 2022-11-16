/**
 * @Author: wzx
 * @Description:
 * @Version: 1.0.0
 * @Date: 2021/5/17 下午6:58
 *@Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
 */

package network

import (
	"MIS-BC/common"
	"MIS-BC/security/keymanager"
	"encoding/json"
	"net"
	"sync"
)

type ConnPool struct {
	ConnMap map[string]Connect
	Mu      sync.Mutex
}

func NewConnPool() *ConnPool {
	return &ConnPool{
		ConnMap: make(map[string]Connect),
	}
}

var DefaultConnPool = NewConnPool()

type Net interface {
	Listen(portOrPrefix string) error
	Listens(portOrPrefix string, sslPortOrPrefix string, key *keymanager.KeyManager) error
	AcceptTCP() (Connect, error)
	Dial(host string) (Connect, error)
	Dials(host string, sslHost string, key *keymanager.KeyManager, serverPubKey []byte) (Connect, error)
}

type Connect interface {
	Read() ([]byte, error)
	readSSL() ([]byte, error)
	Write([]byte) error
	write([]byte) error
	GetRemote() string
	Close() error
	GetConn() *net.TCPConn
}

func SendRequest(request *NetRequest, conn Connect) error {
	b, _ := json.Marshal(request)
	err := conn.Write(b)
	if err != nil {
		common.Logger.Error("Error send message", err.Error())
		return err
	}

	return nil
}

func GetResponse(conn Connect) (*NetResponse, error) {
	buf, err := conn.Read()
	if err != nil {
		common.Logger.Error("Error Reading", err.Error())
		return nil, err
	}

	var response NetResponse
	err = json.Unmarshal(buf, &response)
	if err != nil {
		common.Logger.Error("parse response fail", err.Error())
		return nil, err
	}

	return &response, nil
}
