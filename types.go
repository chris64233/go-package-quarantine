package packagequarantine

import "regexp"

// Version 是软件包某个具体版本的完整身份：名称、版本号与内容摘要共同唯一确定。
// 同一 (Name, Version) 一经发布，其 Digest 不可再更改（不可变性）。
type Version struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// key 是版本在存储中的唯一键。由于 (name, version) 与 digest 一一对应，
// 键中无需包含 digest。
func (v Version) key() string { return v.Name + "@" + v.Version }

// String 返回 name@version(digest) 形式的可读表示。
func (v Version) String() string {
	return v.Name + "@" + v.Version + "(" + v.Digest + ")"
}

// Dependency 是发布请求中声明的直接依赖引用。
// 发布时仅按 (Name, Version) 定位，解析后会得到带摘要的具体 Version。
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (d Dependency) key() string { return d.Name + "@" + d.Version }

// digestPattern 限定内容摘要格式：sha256: 加 64 位十六进制。
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validDigest(d string) bool { return digestPattern.MatchString(d) }
