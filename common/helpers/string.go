package helpers

import (
	"crypto/md5"
	"encoding/hex"
	"unsafe"
)

func StrToBytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

// https://segmentfault.com/a/1190000005006351
func BytesToStr(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func GetMD5Hash(str string) string {
	s := md5.Sum(StrToBytes(str))
	return hex.EncodeToString(s[:])
}
