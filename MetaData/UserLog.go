package MetaData

import (
	"fmt"
)

//go:generate msgp
type UserLog struct {
	// 必需字段
	IdentityIdentifier string `msg:"identityidentifier"`
	Command            string `msg:"command"`

	UGroupID   int    `msg:"ugroupid"`
	Name       string `msg:"name"`
	Source     string `msg:"source"`
	Data       string `msg:"data"`
	Permission string `msg:"permission"`
	Level      int    `msg:"level"`
	Timestamp  string `msg:"timestamp"`

	// 不必需
	Destination   string `msg:"destination"`
	Protocol      string `msg:"protocol"`
	WebSite       string `msg:"website"`
	FilterWebSite string `msg:"filterwebsite"`
	WarnInfo      string `msg:"warninfo"`
	IsInner       int    `msg:"isinner"`
}

func (l UserLog) ToByteArray() []byte {
	data, _ := l.MarshalMsg(nil)
	return data
}

func (l *UserLog) FromByteArray(data []byte) {
	_, err := l.UnmarshalMsg(data)
	if err != nil {
		fmt.Println("err=", err)
	}
}
