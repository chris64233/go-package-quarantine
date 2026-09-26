package packagequarantine

import "time"

// PackageID 软件包版本的唯一坐标：名称 + 版本号 + 内容摘要，三者共同唯一确定一个版本。
type PackageID struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

func (p PackageID) String() string {
	return p.Name + "@" + p.Version + "#" + p.Digest
}

// DepSpec 发布请求中的依赖声明（名称 + 版本号），发布时解析为确切的 PackageID。
type DepSpec struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// PackageVersion 已发布的版本，发布后不可更改；Deps 为解析后的直接依赖。
type PackageVersion struct {
	ID          PackageID   `json:"id"`
	Deps        []PackageID `json:"deps"`
	PublishedAt time.Time   `json:"published_at"`
	Seq         uint64      `json:"seq"`
}

// QuarantineRecord 一条隔离记录。同一版本可存在多条生效中的隔离记录，
// 解除其中一条不会恢复仍被其他隔离路径影响的版本。
type QuarantineRecord struct {
	ID        string     `json:"id"`
	Target    PackageID  `json:"target"`
	Reason    string     `json:"reason"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	LiftedAt  *time.Time `json:"lifted_at,omitempty"`
}

// Exclusion 描述一个被隔离排除的版本，并给出可解释的依赖路径。
type Exclusion struct {
	Package      PackageID `json:"package"`
	QuarantineID string    `json:"quarantine_id"`
	Reason       string    `json:"reason"`
	// Path 从被排除版本出发、沿直接依赖到达被隔离目标的路径（含两端）。
	Path []PackageID `json:"path"`
}

// Resolution 一次依赖解析的结果，基于 SecurityRevision 对应的同一安全快照。
type Resolution struct {
	Name string `json:"name"`
	// Selected 解析选中的版本；全部候选均被隔离时为 nil。
	Selected *PackageVersion `json:"selected,omitempty"`
	// Closure 选中版本的传递依赖闭包（按坐标排序，不含选中版本自身）。
	Closure []PackageID `json:"closure,omitempty"`
	// Excluded 被隔离排除的候选版本及其解释路径。
	Excluded []Exclusion `json:"excluded,omitempty"`
	// SecurityRevision 本次解析读取的安全修订号。
	SecurityRevision uint64 `json:"security_revision"`
}

// ImpactReport 影响查询的结果：针对某版本的生效隔离记录，以及被波及的版本。
type ImpactReport struct {
	Target      PackageID          `json:"target"`
	Quarantines []QuarantineRecord `json:"quarantines"`
	Affected    []Exclusion        `json:"affected"`
}

// AuditEntry 审计历史条目，记录每次改变状态的操作。
type AuditEntry struct {
	Seq              uint64    `json:"seq"`
	Time             time.Time `json:"time"`
	Op               string    `json:"op"` // publish / quarantine / lift
	RequestID        string    `json:"request_id"`
	Detail           string    `json:"detail"`
	SecurityRevision uint64    `json:"security_revision"`
}
