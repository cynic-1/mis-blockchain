package Message

import "fmt"

//go:generate msgp
type QueryTCMPubkeyMsg struct {
	Type      int      `msg:"type"`
	Pubkey    [65]byte `msg:"pubkey"`
	PubkeyLen uint32   `msg:"pubkeylen"`
	NodeID    uint64   `msg:"nodeid"`
}

func (gm QueryTCMPubkeyMsg) ToByteArray() ([]byte, error) {
	data, _ := gm.MarshalMsg(nil)
	return data, nil
}

func (gm *QueryTCMPubkeyMsg) FromByteArray(data []byte) error {
	_, err := gm.UnmarshalMsg(data)
	if err != nil {
		fmt.Println("err=", err)
	}
	return err
}
