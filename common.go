package payment

import (
	"math/rand"
	"time"
)

var rs string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

//获得当前时间戳
func TimeNow() int64 {
	return time.Now().Unix()
}

func TimeString(d int64) string {
	now := time.Now().Unix() + d
	return time.Unix(now, 0).Format("20060102150405")
}

//获得随机字符串
func RandStr() string {
	s := ""
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 32; i++ {
		v := rand.Int() % len(rs)
		s += string(rs[v])
	}
	return s
}
