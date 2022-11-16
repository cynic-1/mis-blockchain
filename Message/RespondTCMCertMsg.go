package Message

import "fmt"

//go:generate msgp
type RespondTCMCertMsg struct {
	WorkerNumber uint32 `msg:"workernumber"`
	Attestation  []byte `msg:"attestation"`
}

func (gm RespondTCMCertMsg) ToByteArray() ([]byte, error) {
	data, _ := gm.MarshalMsg(nil)
	return data, nil
}

func (gm *RespondTCMCertMsg) FromByteArray(data []byte) error {
	_, err := gm.UnmarshalMsg(data)
	if err != nil {
		fmt.Println("err=", err)
	}
	return err
}
