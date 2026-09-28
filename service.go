// Package packagequarantine 实现会沿依赖图传播的软件包版本隔离服务。
//
// 核心模型：
//   - 软件包版本由 (名称, 版本号, 内容摘要) 唯一确定，发布后不可变；
//   - 发布时保存解析后的直接依赖，依赖不存在或构成环都会导致发布失败；
//   - 安全事件隔离某一具体版本，隔离效果沿依赖图正向传播：任何（传递）依赖到
//     被隔离版本的版本都会在安装解析中被排除；
//   - 同一版本可叠加多条不同“隔离原因”的风险，每条风险独立解除、独立豁免；
//   - 有期限的风险豁免（waiver）经批准后临时放开“某版本的某一条隔离原因”，
//     不覆盖该版本后来出现的新风险，也不覆盖其它版本上的风险；
//   - 每次隔离/解除/豁免授予/豁免撤销都使安全修订号 +1，解析在进入时获取一份
//     不可变快照，全程只读取该快照；豁免是否到期则在每次解析入口按当时时钟
//     统一判定一次，解析进行中到期不会返回已失效版本；
//   - 发布、隔离、解除、豁免授予/撤销均要求携带外部请求号实现幂等，同号异内容
//     返回冲突。
package packagequarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pkgVersion 是版本在存储内部的形态：版本身份 + 解析后的直接依赖。
// 创建后不再修改，因此可以被快照安全共享。
type pkgVersion struct {
	Version      Version   `json:"version"`
	Deps         []Version `json:"deps"` // 已解析（带摘要）的直接依赖，保持声明顺序
	PublishedAt  time.Time `json:"published_at"`
	PublishReqID string    `json:"publish_req_id"`
}

// requestRecord 记录外部请求号与已应用操作的对应关系，用于幂等重放与冲突检测。
type requestRecord struct {
	ReqID     string    `json:"req_id"`
	Op        string    `json:"op"` // publish | quarantine | release | release_risk | waiver_grant | waiver_revoke
	Hash      string    `json:"hash"`
	Ref       string    `json:"ref"` // publish: 版本键；其它操作: 事件序号
	CreatedAt time.Time `json:"created_at"`
}

// 安全事件类型。
const (
	OpQuarantine   = "quarantine"
	OpRelease      = "release"
	OpReleaseRisk  = "release_risk"
	OpWaiverGrant  = "waiver_grant"
	OpWaiverRevoke = "waiver_revoke"
)

// SecurityEvent 是一条审计历史：隔离、解除或豁免授予/撤销事件。
type SecurityEvent struct {
	Seq  int    `json:"seq"` // 全局单调递增的事件序号
	Rev  int    `json:"rev"` // 应用该事件后的安全修订号
	Kind string `json:"kind"`
	// quarantine / release / release_risk: 操作备注；
	// waiver_grant / waiver_revoke: 申请/撤销备注。
	Reason string  `json:"reason,omitempty"`
	Target Version `json:"target"`
	ReqID  string  `json:"req_id"` // 外部请求号

	// RiskReason 仅用于豁免事件：被豁免的那一条隔离原因（与 Target 共同定位风险）。
	RiskReason string `json:"risk_reason,omitempty"`
	// Waiver 仅用于 waiver_grant：有效期与批准信息。
	Waiver *WaiverDetail `json:"waiver,omitempty"`

	RelatedSeq int       `json:"related_seq"` // release/release_risk: 解除的 quarantine 序号；waiver_grant: 关联的 quarantine 序号；waiver_revoke: 关联的 grant 序号
	Time       time.Time `json:"time"`
}

// Clock 提供当前时间，便于对豁免到期做确定性测试。生产实现为 time.Now。
type Clock interface {
	Now() time.Time
}

type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }

type utcClock struct{}

func (utcClock) Now() time.Time { return time.Now().UTC() }

// Option 配置 NewService。
type Option func(*serviceConfig)

type serviceConfig struct {
	clock Clock
}

// WithClock 注入时钟（主要用于测试豁免到期）。
func WithClock(c Clock) Option {
	return func(cfg *serviceConfig) { cfg.clock = c }
}

// Service 是软件包隔离服务。零值不可用，请使用 NewService 创建。
type Service struct {
	mu sync.RWMutex

	store *store // 持久化句柄；nil 表示纯内存模式
	clock Clock  // 豁免到期判定时钟

	versions map[string]*pkgVersion // key(name@version) -> 版本
	requests map[string]*requestRecord
	events   []*SecurityEvent // 按 Seq 排序的完整审计历史

	// 当前生效的隔离：版本键 -> (隔离原因 -> quarantine 事件)。
	// 同一版本可因不同原因被多次隔离，每条原因独立存在、独立解除。
	active map[string]map[string]*SecurityEvent
	// 当前未撤销的豁免授予：豁免键(版本+原因) -> 豁免。
	// 到期不改变该映射（到期是时间派生状态）；撤销或被新的有效豁免取代时删除/替换。
	waivers map[string]*Waiver

	securityRev int // 当前安全修订号
	nextSeq     int // 下一个事件序号
}

// NewService 创建服务。dir 为空时使用纯内存模式；否则在 dir 下以 JSONL 持久化
// 图关系（graph.jsonl）、幂等请求（requests.jsonl）与审计历史（audit.jsonl），
// 目录已存在数据时会自动重建状态。
func NewService(dir string, opts ...Option) (*Service, error) {
	cfg := serviceConfig{clock: utcClock{}}
	for _, o := range opts {
		o(&cfg)
	}
	s := &Service{
		clock:    cfg.clock,
		versions: map[string]*pkgVersion{},
		requests: map[string]*requestRecord{},
		active:   map[string]map[string]*SecurityEvent{},
		waivers:  map[string]*Waiver{},
	}
	if dir != "" {
		st, err := openStore(dir)
		if err != nil {
			return nil, err
		}
		s.store = st
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Close 释放持久化资源。
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		err := s.store.close()
		s.store = nil
		return err
	}
	return nil
}

// PublishRequest 是版本发布请求。
type PublishRequest struct {
	RequestID string       // 外部请求号，必填
	Name      string       // 包名，必填
	Version   string       // 版本号，必填
	Digest    string       // 内容摘要，sha256:<64hex>，必填
	Deps      []Dependency // 直接依赖，按 (name, version) 声明，发布时解析为具体版本
}

// PublishResult 是发布结果。Replayed 为 true 表示该外部请求号此前已处理，
// 返回的是重放结果而非新发布。
type PublishResult struct {
	Version  Version
	Deps     []Version // 解析后的直接依赖
	Replayed bool
}

// Publish 发布一个不可变版本。
//
// 失败分类：
//   - KindInvalidParam：字段缺失/格式非法/重复依赖边；
//   - KindDependency：直接依赖不存在，或新节点引入依赖环；
//   - KindDigest：同一 (name,version) 曾以不同摘要发布；
//   - KindIdempotent：RequestID 相同但请求内容不同。
func (s *Service) Publish(req PublishRequest) (*PublishResult, error) {
	if err := validatePublish(req); err != nil {
		return nil, err
	}
	hash := payloadHash("publish", req)

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, ok := s.requests[req.RequestID]; ok {
		if rec.Hash != hash {
			return nil, errf(KindIdempotent,
				"request id %q reused with different content", req.RequestID)
		}
		existing := s.versions[rec.Ref]
		return &PublishResult{Version: existing.Version, Deps: cloneDeps(existing.Deps), Replayed: true}, nil
	}

	v := Version{Name: req.Name, Version: req.Version, Digest: req.Digest}
	k := v.key()
	if existing, ok := s.versions[k]; ok {
		if existing.Version.Digest != v.Digest {
			return nil, errf(KindDigest,
				"version %s already published with digest %s, got %s",
				k, existing.Version.Digest, v.Digest)
		}
		// 同身份同摘要：视为已发布，直接返回（不可变对象天然幂等）。
		return &PublishResult{Version: existing.Version, Deps: cloneDeps(existing.Deps)}, nil
	}

	// 解析直接依赖并做环检测。
	// 新节点尚未入图：图中既有的 DAG 不变，唯一可能出现的环是 new -> ... -> new。
	resolved := make([]Version, 0, len(req.Deps))
	seen := map[string]bool{}
	for _, d := range req.Deps {
		if seen[d.key()] {
			return nil, errf(KindInvalidParam, "duplicate dependency %s", d.key())
		}
		seen[d.key()] = true
		dv, ok := s.versions[d.key()]
		if !ok {
			return nil, errf(KindDependency, "dependency %s does not exist", d.key())
		}
		resolved = append(resolved, dv.Version)
	}
	if cycle := findPathTo(s.versions, resolved, k); cycle != nil {
		path := []Version{v}
		for _, dk := range cycle {
			path = append(path, s.versions[dk].Version)
		}
		return nil, errf(KindDependency, "dependency cycle detected: %s", formatPath(path))
	}

	pv := &pkgVersion{
		Version:      v,
		Deps:         resolved,
		PublishedAt:  s.now(),
		PublishReqID: req.RequestID,
	}
	rec := &requestRecord{
		ReqID:     req.RequestID,
		Op:        "publish",
		Hash:      hash,
		Ref:       k,
		CreatedAt: pv.PublishedAt,
	}
	if err := s.persist(pv, rec); err != nil {
		return nil, err
	}
	s.versions[k] = pv
	s.requests[req.RequestID] = rec
	return &PublishResult{Version: v, Deps: cloneDeps(resolved)}, nil
}

// SecurityResult 是隔离/解除操作的结果。
type SecurityResult struct {
	Event    *SecurityEvent
	Replayed bool // 是否为同一外部请求号的重放
}

// Quarantine 因某一风险原因隔离某一具体版本。版本必须已发布。
//
// 同一版本上相同原因的隔离已生效时返回 KindConflict；
// 不同原因的隔离可以叠加，各自独立解除、独立豁免。
// 成功后安全修订号加一。
func (s *Service) Quarantine(requestID string, target Version, reason string) (*SecurityResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	hash := payloadHash(OpQuarantine, struct {
		Target Version `json:"target"`
		Reason string  `json:"reason"`
	}{target, reason})

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, conflict := s.lookupRequest(requestID, OpQuarantine, hash); conflict != nil {
		return nil, conflict
	} else if rec != nil {
		return &SecurityResult{Event: s.eventBySeq(mustAtoi(rec.Ref)), Replayed: true}, nil
	}

	pv, err := s.lookupVersion(target)
	if err != nil {
		return nil, err
	}
	k := pv.Version.key()
	if ev, ok := s.active[k][reason]; ok {
		return nil, errf(KindConflict,
			"version %s is already quarantined with reason %q by event seq=%d",
			k, reason, ev.Seq)
	}

	ev := s.newEvent(OpQuarantine, pv.Version, requestID, reason, 0)
	rec := s.newRequestRecord(requestID, OpQuarantine, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	if s.active[k] == nil {
		s.active[k] = map[string]*SecurityEvent{}
	}
	s.active[k][reason] = ev
	return &SecurityResult{Event: ev}, nil
}

// Release 解除目标版本上当前生效的隔离。成功后安全修订号加一。
//
// 为保持精确语义：当目标版本上仅有一条生效隔离时，解除它；
// 没有生效隔离返回 KindConflict；存在多条不同原因的隔离时也返回 KindConflict，
// 调用方必须改用 ReleaseRisk 明确要解除哪一条风险原因。
//
// 解除只移除目标版本上的那一条隔离；如果它（或其它版本）仍被其它生效隔离
// 沿依赖路径影响，解析结果不会因此恢复。
func (s *Service) Release(requestID string, target Version, note string) (*SecurityResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	hash := payloadHash(OpRelease, struct {
		Target Version `json:"target"`
		Note   string  `json:"note"`
	}{target, note})

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, conflict := s.lookupRequest(requestID, OpRelease, hash); conflict != nil {
		return nil, conflict
	} else if rec != nil {
		return &SecurityResult{Event: s.eventBySeq(mustAtoi(rec.Ref)), Replayed: true}, nil
	}

	pv, err := s.lookupVersion(target)
	if err != nil {
		return nil, err
	}
	risks := s.active[pv.Version.key()]
	switch len(risks) {
	case 0:
		return nil, errf(KindConflict, "version %s has no active quarantine", pv.Version.key())
	case 1:
		var qEvent *SecurityEvent
		for _, ev := range risks {
			qEvent = ev
		}
		return s.applyRelease(OpRelease, requestID, pv.Version, note, qEvent, hash)
	default:
		reasons := make([]string, 0, len(risks))
		for r := range risks {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		return nil, errf(KindConflict,
			"version %s has %d active quarantines (%s); use ReleaseRisk to name the reason",
			pv.Version.key(), len(risks), strings.Join(reasons, ", "))
	}
}

// ReleaseRisk 精确解除目标版本上指定原因的那一条隔离。成功后安全修订号加一。
// riskReason 必须与某次生效隔离的原因逐字匹配（空原因也用空字符串定位）。
func (s *Service) ReleaseRisk(requestID string, target Version, riskReason, note string) (*SecurityResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	hash := payloadHash(OpReleaseRisk, struct {
		Target     Version `json:"target"`
		RiskReason string  `json:"risk_reason"`
		Note       string  `json:"note"`
	}{target, riskReason, note})

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, conflict := s.lookupRequest(requestID, OpReleaseRisk, hash); conflict != nil {
		return nil, conflict
	} else if rec != nil {
		return &SecurityResult{Event: s.eventBySeq(mustAtoi(rec.Ref)), Replayed: true}, nil
	}

	pv, err := s.lookupVersion(target)
	if err != nil {
		return nil, err
	}
	qEvent, ok := s.active[pv.Version.key()][riskReason]
	if !ok {
		return nil, errf(KindConflict,
			"version %s has no active quarantine with reason %q", pv.Version.key(), riskReason)
	}
	return s.applyRelease(OpReleaseRisk, requestID, pv.Version, note, qEvent, hash)
}

// applyRelease 落盘并提交一条解除事件（调用方已完成幂等与状态检查）。
func (s *Service) applyRelease(kind, requestID string, target Version, note string, qEvent *SecurityEvent, hash string) (*SecurityResult, error) {
	ev := s.newEvent(kind, target, requestID, note, qEvent.Seq)
	if kind == OpReleaseRisk {
		ev.RiskReason = qEvent.Reason // 事件自包含风险原因，回放时无需反查
	}
	rec := s.newRequestRecord(requestID, kind, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	delete(s.active[target.key()], qEvent.Reason)
	if len(s.active[target.key()]) == 0 {
		delete(s.active, target.key())
	}
	// 风险已不存在：挂在它上面的豁免随之失效（授予事件保留在审计历史中）。
	// 这样同原因重新隔离后，必须针对新的隔离事件重新申请豁免。
	delete(s.waivers, waiverKey(target, qEvent.Reason))
	return &SecurityResult{Event: ev}, nil
}

// SecurityRev 返回当前安全修订号。
func (s *Service) SecurityRev() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.securityRev
}

// Snapshot 获取当前状态的不可变快照（含安全修订号、图、生效隔离与未撤销豁免）。
// 一次解析/影响查询的全程只读取返回的这一份快照，期间任何发布、隔离、豁免操作
// 都不会影响它。豁免到期不产生修订事件，由 Resolve/Impact 在入口按当时时钟
// 判定，因此“取快早已到期、取快后到期”都会在执行时被正确拦截。
func (s *Service) Snapshot() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := &Snapshot{
		rev:      s.securityRev,
		clock:    s.clock,
		versions: make(map[string]*pkgVersion, len(s.versions)),
		active:   make(map[string]map[string]*SecurityEvent, len(s.active)),
		waivers:  make(map[string]*Waiver, len(s.waivers)),
		events:   make([]*SecurityEvent, len(s.events)),
	}
	for k, pv := range s.versions {
		snap.versions[k] = pv // pkgVersion 创建后不可变，可直接共享
	}
	for k, risks := range s.active {
		cp := make(map[string]*SecurityEvent, len(risks))
		for reason, ev := range risks {
			e := *ev
			cp[reason] = &e
		}
		snap.active[k] = cp
	}
	for wk, w := range s.waivers {
		cp := *w
		snap.waivers[wk] = &cp
	}
	for i, ev := range s.events {
		cp := *ev
		if ev.Waiver != nil {
			wc := *ev.Waiver
			cp.Waiver = &wc
		}
		snap.events[i] = &cp
	}
	return snap
}

// Snapshot 是某一时刻的只读视图。
type Snapshot struct {
	rev      int
	clock    Clock
	versions map[string]*pkgVersion
	active   map[string]map[string]*SecurityEvent // 版本键 -> 风险原因 -> quarantine 事件
	waivers  map[string]*Waiver                   // 豁免键 -> 未撤销豁免（可能已到期）
	events   []*SecurityEvent
}

// Rev 返回该快照的安全修订号。
func (snap *Snapshot) Rev() int { return snap.rev }

func (snap *Snapshot) now() time.Time {
	if snap.clock != nil {
		return snap.clock.Now().UTC()
	}
	return time.Now().UTC()
}

// Resolution 是成功解析的结果。
type Resolution struct {
	Rev      int       // 解析所基于的安全修订快照
	Root     Version   // 解析起点
	Versions []Version // 需要安装的全部版本（根 + 所有传递依赖），按 key 排序去重

	// Waivers 是本次解析实际采用的全部豁免：闭包内每个被隔离版本上、
	// 用于中和其风险的每一条有效豁免都会记录在此（按版本键、风险原因排序），
	// 含有效期、批准信息与人类可读的采用原因，供调用方留档审计。
	Waivers []AppliedWaiver
}

// AppliedWaiver 说明一次解析为何、依据哪条批准豁免临时采用了某个被隔离版本。
type AppliedWaiver struct {
	Target             Version   // 被豁免的具体版本
	RiskReason         string    // 被放开的那一条隔离原因
	QuarantineEventSeq int       // 被豁免的隔离事件序号
	GrantEventSeq      int       // 豁免授予事件序号
	Rev                int       // 豁免授予后的安全修订号（快照修订号 >= 它）
	ValidFrom          time.Time // 有效期起（含）
	ValidUntil         time.Time // 有效期止（不含）
	Approval           Approval  // 批准信息
	Reason             string    // 人类可读的采用原因
}

// BlockedError 表示根版本在当前快照下被隔离规则排除。
// Path 给出可解释的依赖路径：根版本 → … → 被直接隔离的版本。
// RiskReason 是实际阻断解析的那一条隔离原因（同一版本可能叠加多条风险）。
type BlockedError struct {
	Rev                int
	Path               []Version
	Quarantined        Version
	RiskReason         string
	QuarantineEventSeq int
	Cause              *Error
}

func (e *BlockedError) Error() string { return e.Cause.Error() }
func (e *BlockedError) Unwrap() error { return e.Cause }

// Resolve 在该快照上做安装解析：返回根版本及其全部传递依赖。
// 若根版本被直接隔离（且未被有效豁免覆盖），或其任一传递依赖命中未被豁免的
// 隔离风险，则返回 *BlockedError，其中带有一条从根到被隔离版本的依赖路径
// 以及阻断原因。豁免是否到期以进入 Resolve 时的时钟为准，整次解析只判定一次。
func (snap *Snapshot) Resolve(name, version string) (*Resolution, error) {
	k := name + "@" + version
	root, ok := snap.versions[k]
	if !ok {
		return nil, errf(KindNotFound, "version %s does not exist", k)
	}

	// 整次解析对“到期”只采样一次时钟：结果在时间维度上同样自洽。
	now := snap.now()
	tainted := snap.taintMap(now)
	if hit := tainted[k]; hit != nil {
		path := make([]Version, 0, len(hit.path)+1)
		path = append(path, root.Version)
		for _, dk := range hit.path {
			path = append(path, snap.versions[dk].Version)
		}
		return nil, &BlockedError{
			Rev:                snap.rev,
			Path:               path,
			Quarantined:        path[len(path)-1],
			RiskReason:         hit.reason,
			QuarantineEventSeq: hit.qseq,
			Cause: errf(KindDependency,
				"resolution blocked by quarantine seq=%d reason %q: %s",
				hit.qseq, hit.reason, formatPath(path)),
		}
	}

	// 根未被污染，其整条依赖闭包都不会触及未豁免的被隔离版本（污染分析已覆盖）。
	collected := map[string]Version{k: root.Version}
	var walk func(pv *pkgVersion)
	walk = func(pv *pkgVersion) {
		for _, d := range pv.Deps {
			if _, dup := collected[d.key()]; dup {
				continue
			}
			collected[d.key()] = d
			walk(snap.versions[d.key()])
		}
	}
	walk(root)

	out := make([]Version, 0, len(collected))
	for _, v := range collected {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })

	res := &Resolution{Rev: snap.rev, Root: root.Version, Versions: out}
	res.Waivers = snap.appliedWaivers(collected, now)
	return res, nil
}

// ImpactEntry 描述受目标版本影响的一个（传递）依赖方。
type ImpactEntry struct {
	Version Version   // 受影响的依赖方版本
	Path    []Version // 依赖路径：依赖方 → … → 目标版本
	Blocked bool      // 在当前快照/时钟下该依赖方是否处于被排除状态（可能经由其它隔离路径）
}

// RiskStatus 描述某版本上当前生效的一条隔离风险及其豁免状态。
type RiskStatus struct {
	Reason              string // 隔离原因
	QuarantineEventSeq  int    // 隔离事件序号
	Waived              bool   // 当前是否存在覆盖该风险的有效豁免
	WaiverGrantEventSeq int    // 豁免授予事件序号（未豁免为 0）
	WaiverValidUntil    time.Time
}

// ImpactReport 是影响查询结果。
type ImpactReport struct {
	Rev                 int
	Target              Version
	DirectlyQuarantined bool          // 目标版本当前是否存在任意生效隔离
	QuarantineEventSeq  int           // 恰好一条风险时为其事件序号；零条或多条时为 0
	Risks               []RiskStatus  // 目标版本上的全部生效风险（含豁免状态），按原因排序
	Affected            []ImpactEntry // 所有（传递）依赖到目标版本的版本，按 key 排序
}

// Impact 在该快照上查询影响：谁（传递）依赖了目标版本、各自的依赖路径，
// 以及它们在当前安全修订与当前时钟下是否被排除。目标版本不存在返回 KindNotFound。
func (snap *Snapshot) Impact(name, version string) (*ImpactReport, error) {
	k := name + "@" + version
	target, ok := snap.versions[k]
	if !ok {
		return nil, errf(KindNotFound, "version %s does not exist", k)
	}

	// 构建反向图。
	revAdj := map[string][]string{}
	for dk, pv := range snap.versions {
		for _, d := range pv.Deps {
			revAdj[d.key()] = append(revAdj[d.key()], dk)
		}
	}
	for dks := range revAdj {
		sort.Strings(revAdj[dks])
	}

	now := snap.now()
	tainted := snap.taintMap(now)

	report := &ImpactReport{Rev: snap.rev, Target: target.Version}
	if risks := snap.active[k]; len(risks) > 0 {
		report.DirectlyQuarantined = true
		if len(risks) == 1 {
			for _, ev := range risks {
				report.QuarantineEventSeq = ev.Seq
			}
		}
		report.Risks = make([]RiskStatus, 0, len(risks))
		for reason, ev := range risks {
			st := RiskStatus{Reason: reason, QuarantineEventSeq: ev.Seq}
			if w := snap.matchingWaiver(target.Version, reason, ev.Seq, now); w != nil {
				st.Waived = true
				st.WaiverGrantEventSeq = w.GrantEventSeq
				st.WaiverValidUntil = w.ValidUntil
			}
			report.Risks = append(report.Risks, st)
		}
		sort.Slice(report.Risks, func(i, j int) bool { return report.Risks[i].Reason < report.Risks[j].Reason })
	}

	// 沿反向边 DFS，currentPath 为 [依赖方 ... 起点目标]。
	var dfs func(node string, path []Version)
	dfs = func(node string, path []Version) {
		for _, dependent := range revAdj[node] {
			pv := snap.versions[dependent]
			newPath := append([]Version{pv.Version}, path...)
			report.Affected = append(report.Affected, ImpactEntry{
				Version: pv.Version,
				Path:    append([]Version(nil), newPath...),
				Blocked: tainted[dependent] != nil,
			})
			dfs(dependent, newPath)
		}
	}
	dfs(k, []Version{target.Version})

	sort.Slice(report.Affected, func(i, j int) bool {
		return report.Affected[i].Version.key() < report.Affected[j].Version.key()
	})
	return report, nil
}

// Resolve 是 s.Snapshot().Resolve 的便捷封装：取当前快照做一次安装解析。
// 需要在同一安全修订内完成多步读取时，请显式持有 Snapshot。
func (s *Service) Resolve(name, version string) (*Resolution, error) {
	return s.Snapshot().Resolve(name, version)
}

// Impact 是 s.Snapshot().Impact 的便捷封装。
func (s *Service) Impact(name, version string) (*ImpactReport, error) {
	return s.Snapshot().Impact(name, version)
}

// GetVersion 查询已发布版本及其解析后的直接依赖。
func (snap *Snapshot) GetVersion(name, version string) (Version, []Version, bool) {
	pv, ok := snap.versions[name+"@"+version]
	if !ok {
		return Version{}, nil, false
	}
	return pv.Version, cloneDeps(pv.Deps), true
}

// AuditEvents 返回截至该快照的审计历史（按事件序号排序，隔离/解除/豁免事件）。
func (snap *Snapshot) AuditEvents() []*SecurityEvent {
	out := make([]*SecurityEvent, len(snap.events))
	for i, ev := range snap.events {
		cp := *ev
		if ev.Waiver != nil {
			wc := *ev.Waiver
			cp.Waiver = &wc
		}
		out[i] = &cp
	}
	return out
}

// Waivers 返回该快照上全部未撤销的豁免（含已到期但尚未被新豁免取代的记录），
// 按版本键与风险原因排序。是否在某一时刻有效由 ValidFrom/ValidUntil 判定。
func (snap *Snapshot) Waivers() []*Waiver {
	out := make([]*Waiver, 0, len(snap.waivers))
	for _, w := range snap.waivers {
		cp := *w
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target.key() != out[j].Target.key() {
			return out[i].Target.key() < out[j].Target.key()
		}
		return out[i].RiskReason < out[j].RiskReason
	})
	return out
}

// taintHit 记录一条阻断路径：path 为从被查询版本的直接后继开始、到被直接隔离
// 版本（含）为止的版本键序列；reason/qseq 标识终点上实际阻断的那一条风险。
type taintHit struct {
	path   []string
	reason string
	qseq   int
}

// taintMap 计算污染分析：对每个版本，若它本身带有未被有效豁免覆盖的隔离风险、
// 或沿依赖边可达这样的版本，则记录一条到该风险的路径。返回 nil 表示未污染。
// 图是发布时保证的 DAG，故 memo DFS 必然终止；多条路径时取依赖声明顺序
// 最先发现的一条，同一终点上多条风险时按原因字典序取第一条，保证结果稳定可解释。
func (snap *Snapshot) taintMap(now time.Time) map[string]*taintHit {
	type state int
	const (
		visiting state = iota
		done
	)
	color := map[string]state{}
	memo := map[string]*taintHit{} // nil = 未污染

	var visit func(k string) *taintHit
	visit = func(k string) *taintHit {
		if color[k] == done {
			return memo[k]
		}
		color[k] = visiting
		var hit *taintHit

		// 终点风险：该版本上的每条隔离原因都必须被一条匹配的有效豁免覆盖，
		// 否则该版本仍被这一条未豁免原因阻断。
		reasons := make([]string, 0, len(snap.active[k]))
		for r := range snap.active[k] {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			qev := snap.active[k][r]
			if w := snap.matchingWaiver(snap.versions[k].Version, r, qev.Seq, now); w == nil {
				hit = &taintHit{reason: r, qseq: qev.Seq} // 终点：自身之后无节点
				break
			}
		}

		// 该版本自身的风险即便全部被豁免，仍要继续检查其依赖：
		// 豁免只放开它自己的那一条风险，不替依赖项背书。
		if hit == nil {
			pv := snap.versions[k]
			for _, d := range pv.Deps {
				dk := d.key()
				child := visit(dk)
				if child != nil {
					hit = &taintHit{
						path:   append([]string{dk}, child.path...),
						reason: child.reason,
						qseq:   child.qseq,
					}
					break
				}
			}
		}
		color[k] = done
		memo[k] = hit
		return hit
	}
	for k := range snap.versions {
		visit(k)
	}
	return memo
}

// matchingWaiver 返回在 now 时刻覆盖“指定版本 + 指定隔离原因 + 指定隔离事件”
// 的有效豁免；不存在、已撤销、已到期/未生效，或豁免指向另一条隔离事件时返回 nil。
// 最后一个条件保证：风险解除后又以相同原因重新隔离时，旧豁免不会自动覆盖新风险。
func (snap *Snapshot) matchingWaiver(target Version, reason string, quarantineSeq int, now time.Time) *Waiver {
	w := snap.waivers[waiverKey(target, reason)]
	if w == nil || w.QuarantineEventSeq != quarantineSeq {
		return nil
	}
	if !w.validAt(now) {
		return nil
	}
	return w
}

// appliedWaivers 枚举一次成功解析闭包内实际采用的全部豁免。
// 能成功解析意味着闭包内被隔离版本上的每条风险都有匹配的有效豁免。
func (snap *Snapshot) appliedWaivers(closure map[string]Version, now time.Time) []AppliedWaiver {
	var out []AppliedWaiver
	for ck := range closure {
		pv := snap.versions[ck]
		reasons := make([]string, 0, len(snap.active[ck]))
		for r := range snap.active[ck] {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			qev := snap.active[ck][r]
			w := snap.matchingWaiver(pv.Version, r, qev.Seq, now)
			if w == nil {
				// 与 taintMap 结论矛盾时不应发生：保守起见跳过而非给出虚假豁免记录。
				continue
			}
			out = append(out, AppliedWaiver{
				Target:             pv.Version,
				RiskReason:         r,
				QuarantineEventSeq: qev.Seq,
				GrantEventSeq:      w.GrantEventSeq,
				Rev:                snap.rev,
				ValidFrom:          w.ValidFrom,
				ValidUntil:         w.ValidUntil,
				Approval:           w.Approval,
				Reason:             formatWaiverReason(pv.Version, r, qev.Seq, w),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target.key() != out[j].Target.key() {
			return out[i].Target.key() < out[j].Target.key()
		}
		return out[i].RiskReason < out[j].RiskReason
	})
	return out
}

func formatWaiverReason(target Version, reason string, qSeq int, w *Waiver) string {
	return "临时采用 " + target.String() + "：隔离事件 #" + itoa(qSeq) +
		" 的风险原因 " + strconv.Quote(reason) +
		" 经 " + w.Approval.By +
		" 批准（批准单 " + blankAsDash(w.Approval.ID) + "，事件 #" + itoa(w.GrantEventSeq) + "），" +
		"有效期 " + w.ValidFrom.Format(time.RFC3339) + " 至 " + w.ValidUntil.Format(time.RFC3339)
}

func blankAsDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// ---- 内部辅助 ----

func (s *Service) now() time.Time {
	if s.clock != nil {
		return s.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) lookupRequest(reqID, op, hash string) (*requestRecord, error) {
	rec, ok := s.requests[reqID]
	if !ok {
		return nil, nil
	}
	if rec.Op != op || rec.Hash != hash {
		return nil, errf(KindIdempotent, "request id %q reused with different content", reqID)
	}
	return rec, nil
}

func (s *Service) lookupVersion(target Version) (*pkgVersion, error) {
	pv, ok := s.versions[target.key()]
	if !ok {
		return nil, errf(KindNotFound, "version %s does not exist", target.key())
	}
	if pv.Version.Digest != target.Digest {
		return nil, errf(KindDigest,
			"digest mismatch for %s: stored %s, request %s",
			target.key(), pv.Version.Digest, target.Digest)
	}
	return pv, nil
}

func (s *Service) newEvent(kind string, target Version, reqID, reason string, related int) *SecurityEvent {
	s.nextSeq++
	return &SecurityEvent{
		Seq:        s.nextSeq,
		Rev:        s.securityRev + 1,
		Kind:       kind,
		Reason:     reason,
		Target:     target,
		ReqID:      reqID,
		RelatedSeq: related,
		Time:       s.now(),
	}
}

func (s *Service) newRequestRecord(reqID, op, hash string, ev *SecurityEvent) *requestRecord {
	return &requestRecord{
		ReqID:     reqID,
		Op:        op,
		Hash:      hash,
		Ref:       itoa(ev.Seq),
		CreatedAt: ev.Time,
	}
}

// appendEvent 提交已持久化的安全事件并推进修订号。
func (s *Service) appendEvent(ev *SecurityEvent, rec *requestRecord) {
	s.events = append(s.events, ev)
	s.requests[rec.ReqID] = rec
	s.securityRev = ev.Rev
}

// eventBySeq 按事件序号取事件（序号从 1 开始，与切片索引相差 1）。
func (s *Service) eventBySeq(seq int) *SecurityEvent { return s.events[seq-1] }

func (s *Service) persist(pv *pkgVersion, rec *requestRecord) error {
	if s.store == nil {
		return nil
	}
	if err := s.store.appendGraph(pv); err != nil {
		return err
	}
	return s.store.appendRequests(rec)
}

func (s *Service) persistSecurity(ev *SecurityEvent, rec *requestRecord) error {
	if s.store == nil {
		return nil
	}
	if err := s.store.appendAudit(ev); err != nil {
		return err
	}
	return s.store.appendRequests(rec)
}

// validatePublish 校验发布参数。
func validatePublish(req PublishRequest) error {
	if strings.TrimSpace(req.RequestID) == "" {
		return errf(KindInvalidParam, "request id is required")
	}
	if strings.TrimSpace(req.Name) == "" {
		return errf(KindInvalidParam, "package name is required")
	}
	if strings.TrimSpace(req.Version) == "" {
		return errf(KindInvalidParam, "version is required")
	}
	if !validDigest(req.Digest) {
		return errf(KindInvalidParam, "digest must be sha256:<64 lowercase hex chars>, got %q", req.Digest)
	}
	dedup := map[string]bool{}
	for _, d := range req.Deps {
		if strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Version) == "" {
			return errf(KindInvalidParam, "dependency name and version are required")
		}
		if d.Name == req.Name && d.Version == req.Version {
			return errf(KindDependency, "version %s cannot depend on itself", req.Name+"@"+req.Version)
		}
		if dedup[d.key()] {
			return errf(KindInvalidParam, "duplicate dependency %s", d.key())
		}
		dedup[d.key()] = true
	}
	return nil
}

func validateSecurityOp(requestID string, target Version) error {
	if strings.TrimSpace(requestID) == "" {
		return errf(KindInvalidParam, "request id is required")
	}
	if strings.TrimSpace(target.Name) == "" || strings.TrimSpace(target.Version) == "" {
		return errf(KindInvalidParam, "target name and version are required")
	}
	if !validDigest(target.Digest) {
		return errf(KindInvalidParam, "target digest must be sha256:<64 lowercase hex chars>")
	}
	return nil
}

// findPathTo 检查从 starts 中任一键出发、沿依赖图是否能到达目标键 target，
// 能则返回一条从某个起点到 target（含两端）的版本键路径。
func findPathTo(versions map[string]*pkgVersion, starts []Version, target string) []string {
	type frame struct {
		k    string
		path []string
	}
	visited := map[string]bool{}
	for _, st := range starts {
		stack := []frame{{st.key(), []string{st.key()}}}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if cur.k == target {
				return cur.path
			}

			if visited[cur.k] {
				continue
			}
			visited[cur.k] = true
			pv := versions[cur.k]
			// 逆序压栈以保持依赖声明顺序的优先探索
			for i := len(pv.Deps) - 1; i >= 0; i-- {
				dk := pv.Deps[i].key()
				stack = append(stack, frame{k: dk, path: append(append([]string{}, cur.path...), dk)})
			}
		}
	}
	return nil
}

func cloneDeps(deps []Version) []Version {
	if len(deps) == 0 {
		return []Version{}
	}
	out := make([]Version, len(deps))
	copy(out, deps)
	return out
}

func formatPath(path []Version) string {
	parts := make([]string, len(path))
	for i, v := range path {
		parts[i] = v.key()
	}
	return strings.Join(parts, " -> ")
}

// payloadHash 计算操作负载的规范化哈希，用于幂等冲突判定。
// 固定结构的 json.Marshal 输出是确定的。
func payloadHash(op string, payload any) string {
	b, err := json.Marshal(struct {
		Op      string `json:"op"`
		Payload any    `json:"payload"`
	}{op, payload})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
