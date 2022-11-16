package Message

import "fmt"

//go:generate msgp
type RequestTCMCertMsg struct {
	Timestamp float64 `msg:"timestamp"`
}

func (gm RequestTCMCertMsg) ToByteArray() ([]byte, error) {
	data, _ := gm.MarshalMsg(nil)
	return data, nil
}

func (gm *RequestTCMCertMsg) FromByteArray(data []byte) error {
	_, err := gm.UnmarshalMsg(data)
	if err != nil {
		fmt.Println("err=", err)
	}
	return err
}
