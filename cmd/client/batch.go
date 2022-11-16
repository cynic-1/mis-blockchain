package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/gosuri/uitable"
	"github.com/peterh/liner"
	"github.com/smallnest/rpcx/client"
	"github.com/smallnest/rpcx/protocol"
	"log"
	"os"
	"strconv"
	"time"
)

type User struct {
	Name   string
	Passwd string
}

// String defines a string flag with specified name, default value, and usage string.
// The return value is the address of a string variable that stores the value of the flag.
var (
	addr = flag.String("addr", "localhost:5020", "server address")
)

// 发送参数结构体
type Args struct {
	IdentityIdentifier string
	Prikey             string
	Pubkey             string
	Passwd             string
}

// 通用回复结构体
type CommonResponse struct {
	Code    int
	Message string
	Data    interface{}
}

func main() {
	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(true)

	var number string
	if num, err := line.Prompt("How many identities do you want to register？ "); err == nil {
		log.Print("Got Number: ", num)
		number = num
		line.AppendHistory(num)
	} else if err == liner.ErrPromptAborted {
		log.Print("Aborted")
	} else {
		log.Print("Error reading line: ", err)
	}
	n, err := strconv.Atoi(number)
	if err != nil {
		log.Print("The input is not a valid number：", err)
		os.Exit(1)
	}
	var users []User

	for i := 0; i < n; i++ {
		var user User
		if name, err := line.Prompt("Please enter the identifier of the " + strconv.Itoa(i+1) + "th identity: "); err == nil {
			log.Print("Got IdentityIdentifier: ", name)
			user.Name = name
			line.AppendHistory(name)
		} else if err == liner.ErrPromptAborted {
			log.Print("Aborted")
			break
		} else {
			log.Print("Error reading line: ", err)
			break
		}

		if passwd, err := line.Prompt("Please enter the password of the " + strconv.Itoa(i+1) + "th identity: "); err == nil {
			log.Print("Got Password: ", passwd)
			user.Passwd = passwd
			line.AppendHistory(passwd)
		} else if err == liner.ErrPromptAborted {
			log.Print("Aborted")
			break
		} else {
			log.Print("Error reading line: ", err)
			break
		}
		users = append(users, user)
	}

	table := uitable.New()
	table.MaxColWidth = 100
	table.RightAlign(10)
	table.AddRow("Name", "Passwd")
	for _, user := range users {
		table.AddRow(color.GreenString(user.Name), color.RedString(user.Passwd))
	}
	fmt.Println("Please make sure you want to register for the following identities: ")
	fmt.Println(table)

	if choice, err := line.Prompt("Whether to enter the registration stage？（Yes/No）: "); err == nil {
		log.Print("Got : ", choice)
		line.AppendHistory(choice)
		if choice == "Yes" {
			err = batchIdentityRegistry(users)
		}
	} else if err == liner.ErrPromptAborted {
		log.Print("Aborted")
	} else if err != nil {
		log.Print("Error reading line: ", err)
	}
}

func batchIdentityRegistry(users []User) error {
	flag.Parse()
	//定义了使用什么方式来实现服务发现。 在这里我们使用最简单的 Peer2PeerDiscovery（点对点）。客户端直连服务器来获取服务地址。
	d, _ := client.NewPeer2PeerDiscovery("tcp@"+*addr, "")
	opt := client.DefaultOption
	opt.SerializeType = protocol.JSON
	//创建了 XClient， 并且传进去了 FailMode、 SelectMode 和默认选项。
	//FailMode 告诉客户端如何处理调用失败：重试、快速返回，或者 尝试另一台服务器。
	//SelectMode 告诉客户端如何在有多台服务器提供了同一服务的情况下选择服务器。

	xclient := client.NewXClient("BatchRegistry", client.Failtry, client.RandomSelect, d, opt)
	defer xclient.Close()

	for _, user := range users {
		args := Args{
			IdentityIdentifier: user.Name,
			Passwd:             user.Passwd,
		}
		reply := &CommonResponse{}
		err := xclient.Call(context.Background(), "BatchIdentityRegistryforTest", args, reply)
		if err != nil {
			log.Fatalf("failed to call: %v", err)
			return err
		}
		log.Printf("%d * %d = %d", reply)
		time.Sleep(5 * time.Second)
	}
	return nil
}
