package packagequarantine

import (
	"errors"
	"fmt"
)

// ErrorKind 区分业务错误类别，便于调用方按类别处理与持久化审计。
type ErrorKind string

const (
	KindInvalidParam ErrorKind = "invalid_param" // 参数错误：字段缺失、格式非法等
	KindDependency   ErrorKind = "dependency"    // 依赖错误：依赖不存在、构成依赖环等
	KindDigest       ErrorKind = "digest"        // 摘要错误：同版本以不同摘要重复发布
	KindIdempotent   ErrorKind = "idempotent"    // 幂等错误：外部请求号相同但内容不同（冲突）
	KindNotFound     ErrorKind = "not_found"     // 查询对象不存在
	KindConflict     ErrorKind = "conflict"      // 其他状态冲突（如重复隔离/解除）
)

// Error 携带分类信息的业务错误。
type Error struct {
	Kind    ErrorKind
	Message string
}

func (e *Error) Error() string { return string(e.Kind) + ": " + e.Message }

// ErrorAs 从任意 error 中取出 *Error，不存在时返回 nil。
func ErrorAs(err error) *Error {
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

func errf(kind ErrorKind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}
