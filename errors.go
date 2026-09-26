package packagequarantine

import (
	"errors"
	"fmt"
)

// ErrorKind 区分错误的类别，便于调用方分别处理参数、依赖、摘要与幂等错误。
type ErrorKind string

const (
	// ErrKindParam 参数错误：缺少必填字段、版本号格式非法等。
	ErrKindParam ErrorKind = "param"
	// ErrKindDependency 依赖错误：依赖不存在、依赖成环、依赖被隔离。
	ErrKindDependency ErrorKind = "dependency"
	// ErrKindDigest 摘要错误：摘要格式非法，或同名同版本的内容摘要不一致。
	ErrKindDigest ErrorKind = "digest"
	// ErrKindIdempotency 幂等冲突：同一外部请求号携带了不同的请求内容。
	ErrKindIdempotency ErrorKind = "idempotency"
	// ErrKindNotFound 目标对象不存在。
	ErrKindNotFound ErrorKind = "not_found"
	// ErrKindState 状态错误：如对已经解除的隔离再次解除。
	ErrKindState ErrorKind = "state"
)

// Error 是服务返回的业务错误，Kind 字段标识错误类别。
type Error struct {
	Kind ErrorKind
	Msg  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Msg)
}

func newError(kind ErrorKind, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...)}
}

// KindOf 提取错误的类别；非本服务产生的错误返回 false。
func KindOf(err error) (ErrorKind, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind, true
	}
	return "", false
}
