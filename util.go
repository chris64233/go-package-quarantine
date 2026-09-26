package packagequarantine

import "strconv"

func itoa(n int) string { return strconv.Itoa(n) }

// mustAtoi 用于内部持久化记录中的事件序号，数据必然合法。
func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic("packagequarantine: corrupted event seq: " + s)
	}
	return n
}
