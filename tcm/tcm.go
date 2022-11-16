package tcm

/*
//#cgo CFLAGS: -DTCM_POSIX=1 -I./lib
//#cgo LDFLAGS: TCMLIB.a TCMALG.a -L. -lftddl
//#include <stdint.h>
//#include "bridge.h"
*/
//import "C"
//import "C"
//import (
//    "MIS-BC/KeyManager"
//    "MIS-BC/utils"
//    "encoding/json"
//    "errors"
//    "os"
//    "os/exec"
//    "strings"
//    "unsafe"
//)
//
//type Tcm struct {
//    ExeHashList    map[uint64]string
//}
//
//type attestation struct {
//    Exehash    string
//    Timestamp   float64
//    Sig         [64]byte
//}
//
//func IsTCMExist() bool {
//    cmd := "lsmod | grep ax99100_spi"
//    out, _ := exec.Command("bash","-c",cmd).Output()
//    if len(out) > 0 {
//        return true
//    } else {
//        return false
//    }
//}
//
//func ForceClear() int32 {
//    return int32(C.ForceClear())
//}
//
//func Init(mode uint8) int32 {
//    return int32(C.init(C.uint8_t(mode)))
//}
//
//func CreateAsymmKey(key_index *uint32) int32 {
//    p := unsafe.Pointer(key_index)
//    return int32(C.CreateAsymmKey((*C.uint32_t)(p)))
//}
//
//func GetPubkey(key_index uint32, pubkey unsafe.Pointer, pubkeyLen unsafe.Pointer) int32 {
//    return int32(C.GetPubkey((C.uint32_t)(key_index), (*C.uint8_t)(pubkey), (*C.uint32_t)(pubkeyLen)))
//}
//
//func Sign(sign_data unsafe.Pointer, sign_len uint32, sign_value unsafe.Pointer, value_len unsafe.Pointer, prikey_index uint32) int32 {
//    return int32(C.Sign((*C.uint8_t)(sign_data), (C.uint32_t)(sign_len), (*C.uint8_t)(sign_value), (*C.uint32_t)(value_len), (C.uint32_t)(prikey_index)))
//}
//
//func Verify(sign_data unsafe.Pointer, sign_len uint32, sign_value unsafe.Pointer, value_len uint32, pubkey unsafe.Pointer, pubkeyLen uint32) int32 {
//    return int32(C.Verify((*C.uint8_t)(sign_data), (C.uint32_t)(sign_len), (*C.uint8_t)(sign_value), (C.uint32_t)(value_len), (*C.uint8_t)(pubkey), (C.uint32_t)(pubkeyLen)))
//}
//
//func getExecHash() (string, error) {
//    execpath, err := os.Executable()
//    if err != nil {
//        return "", err
//    }
//    cmd := exec.Command("sha256sum",execpath)
//    out, err := cmd.CombinedOutput()
//    if err != nil {
//        return "", err
//    }
//    return strings.Split(string(out), " ")[0], nil
//}
//
//func GetMyAttestation(index uint32) ([]byte, error) {
//    var myAttestation attestation
//    exehash, err := getExecHash()
//    if err != nil {
//        return nil, err
//    }
//    myAttestation.Exehash = exehash
//    myAttestation.Timestamp = utils.GetCurrentTime()
//    data, err := json.Marshal(myAttestation)
//    if err != nil {
//        return nil, err
//    }
//    hash := KeyManager.GetHash(data)
//    var realHash = [32]byte{0}
//    for i:=0; i<32; i++ {
//        realHash[i] = hash[i]
//    }
//    var sign_value = [64]byte{0}
//    var value_len uint32 = 0
//    ret := Init(2)
//    if ret != 0 {
//        return nil, errors.New("tcm.Init")
//    }
//    ret = Sign(unsafe.Pointer(&realHash), 32, unsafe.Pointer(&sign_value), unsafe.Pointer(&value_len), index)
//    if ret != 0 {
//        return nil, errors.New("tcm.Sign")
//    }
//    myAttestation.Sig = sign_value
//
//    res, err := json.Marshal(myAttestation)
//    if err != nil {
//        return nil, err
//    }
//    return res, nil
//}
//
//func (tcm *Tcm) VerifyAttestation(raw []byte, tcmpubkey [65]byte, nodeId uint64) (bool, error) {
//    orignalAttestation := attestation{}
//    err := json.Unmarshal(raw, &orignalAttestation)
//    if err != nil {
//        return false, err
//    }
//
//    var newAttestation attestation
//    newAttestation.Exehash = orignalAttestation.Exehash
//    newAttestation.Timestamp = orignalAttestation.Timestamp
//
//    data, err := json.Marshal(newAttestation)
//    if err != nil {
//        return false, err
//    }
//    hash := KeyManager.GetHash(data)
//    var realHash = [32]byte{0}
//    for i:=0; i<32; i++ {
//        realHash[i] = hash[i]
//    }
//    ret:= Verify(unsafe.Pointer(&realHash), 32, unsafe.Pointer(&orignalAttestation.Sig), 64, unsafe.Pointer(&tcmpubkey), 65)
//    if ret != 0 {
//        return false, errors.New("tcm验签错误")
//    }
//
//    real_exehash, ok := tcm.ExeHashList[nodeId]
//    if !ok {
//        tcm.ExeHashList[nodeId] = orignalAttestation.Exehash
//        return true, nil
//    }
//
//    if orignalAttestation.Exehash == real_exehash {
//        return true, nil
//    } else {
//        return false, nil
//    }
//}
