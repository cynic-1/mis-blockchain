package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"minlib/minsecurity/crypto/sm4"
	"os"
	"strconv"
	"time"
)

const TIME_LAYOUT = "2006-01-02 15:04:05"

//

func Uint64ToString(i uint64) string {
	return strconv.FormatUint(i, 10)
}

func Uint64ToBytes(i uint64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, i)
	return buf
}

func IntToBytes(i int) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}

func BytesToInt(buf []byte) int {
	return int(binary.BigEndian.Uint32(buf))
}
func BytesToUint64(buf []byte) uint64 {
	return binary.BigEndian.Uint64(buf)
}

func BytesToHex(data []byte) (dst string) {
	return hex.EncodeToString(data)
}
func HexToBytes(data string) (dst []byte, err error) {
	return hex.DecodeString(data)
}

//获取时间戳,单位为秒
func GetCurrentTime() float64 {
	return float64(time.Now().UTC().Unix())
}

//获取时间戳,单位为毫秒
func GetCurrentTimeMilli() float64 {
	return float64(time.Now().UTC().UnixNano()) / 1e6
}

//根据时间字符串和指定时区转换Time
func ParseWithLocation(name string, timeStr string) (time.Time, error) {
	locationName := name
	if l, err := time.LoadLocation(locationName); err != nil {
		println(err.Error())
		return time.Time{}, err
	} else {
		lt, _ := time.ParseInLocation(TIME_LAYOUT, timeStr, l)
		return lt, nil
	}
}

func EncryptString(source string) string {
	out, err := sm4.Sm4Ecb([]byte("1234567890123456"), []byte(source), sm4.ENC)
	if err != nil {
		fmt.Println("sm4 error, ", err)
		return ""
	}
	return hex.EncodeToString(out)
}

func DecryptString(source string) string {
	b, err := hex.DecodeString(source)
	if err != nil {
		fmt.Println("hex decode error,", err)
		return ""
	}

	out, err := sm4.Sm4Ecb([]byte("1234567890123456"), b, sm4.DEC)
	if err != nil {
		fmt.Println("sm4", err)
	}
	return string(out)
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		// 创建文件夹
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			fmt.Printf("mkdir failed![%v]\n", err)
		} else {
			return true, nil
		}
	}
	return false, err
}
