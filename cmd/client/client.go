/**
 * @Author: xzw
 * @Description:
 * @Version: 1.0.0
 * @Date: 2021/12/7 16:00
 * @Copyright: MIN-Group；国家重大科技基础设施——未来网络北大实验室；深圳市信息论与未来网络重点实验室
 */

package main

import (
	"MIS-BC/common"
	"MIS-BC/security/keymanager"
	"context"
	"flag"
	"fmt"
	"github.com/peterh/liner"
	"github.com/smallnest/rpcx/client"
	"github.com/smallnest/rpcx/protocol"
	"github.com/urfave/cli/v2"
	"log"
	"strings"
)

var (
	commandList = [][]string{
		{"identity", "registry", "name", "passwd"},
		{"identity", "dump", "name", "passwd", "prikey"},
		{"identity", "batch", "name", "passwd"},
	}
)

//// String defines a string flag with specified name, default value, and usage string.
//// The return value is the address of a string variable that stores the value of the flag.
//var (
//	addr = flag.String("addr", "localhost:5020", "server address")
//)

// type set
const (
	IDENTITY = "identity"
)

// command set
const (
	REGISTRY = "registry"
	DUMP     = "dump"
	BATCH    = "batch"
)

// method set
const (
	GET    = "GET"
	POST   = "POST"
	DELETE = "DELETE"
	PUT    = "PUT"
)

type Request struct {
	Type       string // 类型
	Command    string // 命令
	Parameters []byte // 参数
}

func main() {
	// define a new liner
	line := liner.NewLiner()
	defer line.Close()
	// ctrl + c exit
	line.SetCtrlCAborts(true)
	// SetCompleter sets the completion function that Liner will call to fetch completion candidates
	// when the user presses tab.
	// Tab 补全输入 会输出所有可能匹配的候选项
	line.SetCompleter(func(li string) (res []string) {
		for _, command := range commandList {
			for _, c := range command {
				if strings.HasPrefix(c, li) {
					res = append(res, strings.ToLower(c))
				}
			}
		}
		return
	})

	prompt := "mis-cli>"
	for {
		//Prompt 显示 prompt 并返回一行用户输入，不包括尾随换行符。
		//如果用户通过按 Ctrl-D 发出文件结束信号，则返回 io.EOF 错误。
		//如果终端支持，提示允许行编辑。
		cmd, err := line.Prompt(prompt)
		if err != nil {
			fmt.Println(err)
			break
		}
		// trim space
		// TrimSpace returns a slice of the string s,
		// with all leading and trailing white space removed, as defined by Unicode.
		// 去掉前后的空格
		cmd = strings.TrimSpace(cmd)
		if len(cmd) == 0 {
			continue
		}
		// transfer to low
		lowerCmd := strings.ToLower(cmd)
		// 解析完命令
		c := strings.Split(cmd, " ")
		// print help or quit.
		if lowerCmd == "quit" {
			fmt.Println("bye")
			break
		} else {
			// execute the command and print the reply.
			// AppendHistory 将一个条目附加到回滚历史记录。 如果 Prompt 返回有效命令，则应调用 AppendHistory。
			line.AppendHistory(cmd)
			app := &cli.App{
				Name:  "mis-cli",
				Usage: "mis cmd tool for identity-act",
				Commands: []*cli.Command{
					identityCommand(),
				},
			}

			c = append([]string{"cmd"}, c...)

			//Run 是 cli 应用程序的入口点。 解析参数切片和路由到正确的标志/参数组合
			err := app.Run(c)
			if err != nil {
				fmt.Printf("(error) %v \n", err)
				break
			}
		}
	}
}

func identityCommand() *cli.Command {
	return &cli.Command{
		Name:  "identity",
		Usage: "identity command",
		Subcommands: []*cli.Command{
			registryIdentityCommand(),
			dumpIdentityCommand(),
			batchIdentityCommand(),
		},
	}
}

func registryIdentityCommand() *cli.Command {
	return &cli.Command{
		Name:  "registry",
		Usage: "registry a new identity",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "the identifier of identity",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "passwd",
				Aliases:  []string{"p"},
				Usage:    "the passwd of identity",
				Required: true,
			},
		},
		Action: registryIdentity,
	}
}

func registryIdentity(c *cli.Context) error {
	flag.Parse()
	//定义了使用什么方式来实现服务发现。 在这里我们使用最简单的 Peer2PeerDiscovery（点对点）。客户端直连服务器来获取服务地址。
	d, _ := client.NewPeer2PeerDiscovery("tcp@"+*addr, "")
	opt := client.DefaultOption
	opt.SerializeType = protocol.JSON
	//创建了 XClient， 并且传进去了 FailMode、 SelectMode 和默认选项。
	//FailMode 告诉客户端如何处理调用失败：重试、快速返回，或者 尝试另一台服务器。
	//SelectMode 告诉客户端如何在有多台服务器提供了同一服务的情况下选择服务器。

	xclient := client.NewXClient("Registry", client.Failtry, client.RandomSelect, d, opt)
	defer xclient.Close()

	var keyManager keymanager.KeyManager
	keyManager.Init()
	keyManager.GenKeyPair()

	name := c.String("name")
	passwd := c.String("passwd")

	args := Args{
		IdentityIdentifier: name,
		Pubkey:             keyManager.GetPubkey(),
		Passwd:             passwd,
	}
	common.Logger.Info(keyManager.GetPubkey(), keyManager.GetPriKey())
	reply := &CommonResponse{}
	err := xclient.Call(context.Background(), "IdentityRegistryforTest", args, reply)
	if err != nil {
		log.Fatalf("failed to call: %v", err)
		return err
	}

	log.Printf("%d * %d = %d", reply)
	return nil
}

func dumpIdentityCommand() *cli.Command {
	return &cli.Command{
		Name:  "dump",
		Usage: "dump a identity",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "the identifier of identity",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "passwd",
				Aliases:  []string{"p"},
				Usage:    "the passwd of identity",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "prikey",
				Aliases:  []string{"k"},
				Usage:    "the prikey of identity",
				Required: true,
			},
		},
		Action: dumpIdentity,
	}
}

func dumpIdentity(c *cli.Context) error {
	flag.Parse()
	//定义了使用什么方式来实现服务发现。 在这里我们使用最简单的 Peer2PeerDiscovery（点对点）。客户端直连服务器来获取服务地址。
	d, _ := client.NewPeer2PeerDiscovery("tcp@"+*addr, "")
	opt := client.DefaultOption
	opt.SerializeType = protocol.JSON
	//创建了 XClient， 并且传进去了 FailMode、 SelectMode 和默认选项。
	//FailMode 告诉客户端如何处理调用失败：重试、快速返回，或者 尝试另一台服务器。
	//SelectMode 告诉客户端如何在有多台服务器提供了同一服务的情况下选择服务器。

	xclient := client.NewXClient("Dump", client.Failtry, client.RandomSelect, d, opt)
	defer xclient.Close()

	name := c.String("name")
	passwd := c.String("passwd")
	prikey := c.String("prikey")

	args := Args{
		IdentityIdentifier: name,
		Passwd:             passwd,
		Prikey:             prikey,
	}
	reply := &CommonResponse{}
	err := xclient.Call(context.Background(), "DumpIdentityforTest", args, reply)
	if err != nil {
		log.Fatalf("failed to call: %v", err)
	}

	log.Printf("%d * %d = %d", reply)

	return nil
}

func batchIdentityCommand() *cli.Command {
	return &cli.Command{
		Name:  "batch",
		Usage: "registry and dump a new identity",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "name",
				Aliases:  []string{"n"},
				Usage:    "the identifier of identity",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "passwd",
				Aliases:  []string{"p"},
				Usage:    "the passwd of identity",
				Required: true,
			},
		},
		Action: batchIdentity,
	}
}

func batchIdentity(c *cli.Context) error {
	flag.Parse()
	//定义了使用什么方式来实现服务发现。 在这里我们使用最简单的 Peer2PeerDiscovery（点对点）。客户端直连服务器来获取服务地址。
	d, _ := client.NewPeer2PeerDiscovery("tcp@"+*addr, "")
	opt := client.DefaultOption
	opt.SerializeType = protocol.JSON
	//创建了 XClient， 并且传进去了 FailMode、 SelectMode 和默认选项。
	//FailMode 告诉客户端如何处理调用失败：重试、快速返回，或者 尝试另一台服务器。
	//SelectMode 告诉客户端如何在有多台服务器提供了同一服务的情况下选择服务器。

	xclient := client.NewXClient("Batch", client.Failtry, client.RandomSelect, d, opt)
	defer xclient.Close()

	var keyManager keymanager.KeyManager
	keyManager.Init()
	keyManager.GenKeyPair()

	name := c.String("name")
	passwd := c.String("passwd")

	args := Args{
		IdentityIdentifier: name,
		Pubkey:             keyManager.GetPubkey(),
		Passwd:             passwd,
	}
	common.Logger.Info(keyManager.GetPubkey(), keyManager.GetPriKey())
	reply := &CommonResponse{}
	err := xclient.Call(context.Background(), "BatchIdentityforTest", args, reply)
	if err != nil {
		log.Fatalf("failed to call: %v", err)
		return err
	}

	log.Printf("%d * %d = %d", reply)
	return nil
}
