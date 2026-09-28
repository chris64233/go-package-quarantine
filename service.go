// Package packagequarantine 实现会沿依赖图传播的软件包版本隔离服务。
//
// 核心模型：
//   - 软件包版本由 (名称, 版本号, 内容摘要) 唯一确定，发布后不可变；
//   - 发布时保存解析后的直接依赖，依赖不存在或构成环都会导致发布失败；
//   - 安全事件隔离某一具体版本（隔离原因是该隔离身份的一部分，同一版本可因
//     不同原因被多条隔离同时命中），隔离效果沿依赖图正向传播：任何（传递）依赖
//     到被隔离版本的版本都会在安装解析中被排除；
//   - 每次隔离/解除/豁免/撤销都使安全修订号 +1，解析在进入时获取一份不可变快照，
//     全程只读取该快照；
//   - 有期限的风险豁免精确关联“具体版本 + 隔离原因（隔离事件序号）”，只放开这
//     一条风险；豁免到期、被撤销，或同一版本出现其它原因的新隔离时，豁免都不能
//     让该版本继续通过解析；
//   - 发布、隔离、解除、豁免申请/撤销均要求携带外部请求号实现幂等，同号异内容
//     返回冲突。
package packagequarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
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
	Op        string    `json:"op"` // publish | quarantine | release | grant_waiver | revoke_waiver
	Hash      string    `json:"hash"`
	Ref       string    `json:"ref"` // publish: 版本键；其它操作: 事件序号
	CreatedAt time.Time `json:"created_at"`
}

// 安全事件类型。
const (
	OpQuarantine   = "quarantine"
	OpRelease      = "release"
	OpGrantWaiver  = "grant_waiver"
	OpRevokeWaiver = "revoke_waiver"
)

// SecurityEvent 是一条审计历史：隔离、解除或豁免相关事件。
type SecurityEvent struct {
	Seq        int       `json:"seq"`         // 全局单调递增的事件序号
	Rev        int       `json:"rev"`         // 应用该事件后的安全修订号
	Kind       string    `json:"kind"`        // quarantine | release | grant_waiver | revoke_waiver
	Target     Version   `json:"target"`      // 被操作的具体版本
	ReqID      string    `json:"req_id"`      // 外部请求号
	Reason     string    `json:"reason"`      // quarantine/grant: 隔离原因；release: 被解除隔离的原因；revoke: 撤销备注
	RelatedSeq int       `json:"related_seq"` // release/grant 关联的 quarantine 序号；revoke 关联的 grant 事件序号
	Time       time.Time `json:"time"`
}

// Service 是软件包隔离服务。零值不可用，请使用 NewService 创建。
type Service struct {
	mu sync.RWMutex

	store *store // 持久化句柄；nil 表示纯内存模式

	versions map[string]*pkgVersion // key(name@version) -> 版本
	requests map[string]*requestRecord
	events   []*SecurityEvent // 按 Seq 排序的完整审计历史

	// 当前生效的隔离：版本键 -> 隔离原因 -> quarantine 事件。
	// 同一版本可因不同原因同时存在多条隔离，解除/豁免都只针对其中一条。
	active map[string]map[string]*SecurityEvent

	// 全部豁免授予记录：grant 事件序号 -> 豁免（撤销时原地更新并追加落盘）。
	waivers map[int]*RiskWaiver

	// 每次成功解析采用豁免的留痕（内存中始终保留，持久化模式同时落盘）。
	waiverUsage []WaiverUsageRecord

	securityRev int // 当前安全修订号
	nextSeq     int // 下一个事件序号

	// nowFn 返回当前时间；nil 时使用 time.Now().UTC()。测试可替换以获得确定的
	// 到期/撤销语义。注意：快照另有自己的采样时刻，nowFn 只影响写入侧（授予、
	// 撤销、发布与事件时间）。
	nowFn func() time.Time
}

// now 返回写入操作使用的当前时间（UTC）。
func (s *Service) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn().UTC()
	}
	return time.Now().UTC()
}

// NewService 创建服务。dir 为空时使用纯内存模式；否则在 dir 下以 JSONL 持久化
// 图关系（graph.jsonl）、幂等请求（requests.jsonl）、审计历史（audit.jsonl）、
// 豁免（waivers.jsonl）与豁免采用留痕（waiver_usage.jsonl），
// 目录已存在数据时会自动重建状态。
func NewService(dir string) (*Service, error) {
	s := &Service{
		versions: map[string]*pkgVersion{},
		requests: map[string]*requestRecord{},
		active:   map[string]map[string]*SecurityEvent{},
		waivers:  map[int]*RiskWaiver{},
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

// SecurityResult 是隔离/解除/撤销操作的结果。
type SecurityResult struct {
	Event    *SecurityEvent
	Replayed bool // 是否为同一外部请求号的重放
}

// Quarantine 因给定原因隔离某一具体版本。版本必须已发布。
//
// 原因是隔离身份的一部分：同一版本可因不同原因被多次隔离，各自独立生效、
// 独立解除/豁免。若该版本当前已有相同原因的生效隔离，返回 KindConflict。
// 成功后安全修订号加一。
func (s *Service) Quarantine(requestID string, target Version, reason string) (*SecurityResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, errf(KindInvalidParam, "quarantine reason is required")
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
	if ev, ok := s.active[pv.Version.key()][reason]; ok {
		return nil, errf(KindConflict,
			"version %s is already quarantined for reason %q by event seq=%d",
			pv.Version.key(), reason, ev.Seq)
	}

	ev := s.newEvent(OpQuarantine, pv.Version, requestID, reason, 0)
	rec := s.newRequestRecord(requestID, OpQuarantine, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	if s.active[pv.Version.key()] == nil {
		s.active[pv.Version.key()] = map[string]*SecurityEvent{}
	}
	s.active[pv.Version.key()][reason] = ev
	return &SecurityResult{Event: ev}, nil
}

// Release 解除目标版本上“指定原因”的那一条隔离。成功后安全修订号加一。
//
// 解除只移除 (版本, 原因) 这一条隔离；同一版本的其它原因隔离、以及其它版本的
// 隔离仍然生效，经它们传播的阻塞不会因此恢复。
func (s *Service) Release(requestID string, target Version, quarantineReason string) (*SecurityResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	if strings.TrimSpace(quarantineReason) == "" {
		return nil, errf(KindInvalidParam, "quarantine reason is required")
	}
	hash := payloadHash(OpRelease, struct {
		Target Version `json:"target"`
		Reason string  `json:"reason"`
	}{target, quarantineReason})

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
	qEvent, ok := s.active[pv.Version.key()][quarantineReason]
	if !ok {
		return nil, errf(KindConflict,
			"version %s has no active quarantine for reason %q",
			pv.Version.key(), quarantineReason)
	}

	ev := s.newEvent(OpRelease, pv.Version, requestID, quarantineReason, qEvent.Seq)
	rec := s.newRequestRecord(requestID, OpRelease, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	delete(s.active[pv.Version.key()], quarantineReason)
	if len(s.active[pv.Version.key()]) == 0 {
		delete(s.active, pv.Version.key())
	}
	return &SecurityResult{Event: ev}, nil
}

// Approval 记录豁免的批准信息。
type Approval struct {
	Approver string    `json:"approver"` // 批准人，必填
	Ticket   string    `json:"ticket"`   // 批准单号/工单号，可选
	Note     string    `json:"note"`     // 批准备注，可选
	Time     time.Time `json:"time"`     // 批准时间；申请时留空则由服务填入授予时间
}

// RiskWaiver 是一条有期限的风险豁免：精确关联某条隔离（具体版本 + 隔离原因 +
// 隔离事件序号），只放开这一条风险，不覆盖同一版本后来出现的任何其它隔离原因。
type RiskWaiver struct {
	// Seq 是授予豁免的审计事件序号，也是豁免的稳定标识。
	Seq int `json:"seq"`
	// QuarantineSeq 是被豁免的那条 quarantine 事件序号（精确关联，不只是原因字符串）。
	QuarantineSeq int       `json:"quarantine_seq"`
	Target        Version   `json:"target"`
	Reason        string    `json:"reason"` // 被豁免的隔离原因
	GrantedAt     time.Time `json:"granted_at"`
	ExpiresAt     time.Time `json:"expires_at"` // 有效期截止；该时刻起豁免失效
	Approval      Approval  `json:"approval"`

	// 撤销信息；RevokedAt 为零值表示未撤销。
	RevokedAt      time.Time `json:"revoked_at,omitempty"`
	RevokedReqID   string    `json:"revoked_req_id,omitempty"`
	RevokeReason   string    `json:"revoke_reason,omitempty"`
	RevokeEventSeq int       `json:"revoke_event_seq,omitempty"`
}

// ActiveAt 报告豁免在时刻 now 是否有效：未撤销且未到期
// （到期时刻本身即失效，故采用严格的 Before 判定）。
func (w *RiskWaiver) ActiveAt(now time.Time) bool {
	return w.RevokedAt.IsZero() && now.Before(w.ExpiresAt)
}

// WaiverGrantResult 是豁免申请结果。
type WaiverGrantResult struct {
	Waiver   *RiskWaiver
	Event    *SecurityEvent
	Replayed bool
}

// GrantWaiver 申请一条有期限的风险豁免。
//
// 豁免精确关联 (target, quarantineReason) 当前生效的那一条隔离（内部以隔离事件
// 序号锁定）。要求：
//   - 该版本当前确实存在该原因的生效隔离，否则 KindConflict；
//   - expiresAt 必须晚于当前时间；Approval.Approver 必填，否则 KindInvalidParam；
//   - 该条隔离尚不存在“未撤销且未到期”的豁免，否则 KindConflict。
//
// 同号 + 同内容重放首次结果且不推进修订号；同号异内容返回 KindIdempotent。
// 成功授予后安全修订号加一。
func (s *Service) GrantWaiver(requestID string, target Version, quarantineReason string,
	expiresAt time.Time, approval Approval) (*WaiverGrantResult, error) {

	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	if strings.TrimSpace(quarantineReason) == "" {
		return nil, errf(KindInvalidParam, "quarantine reason is required")
	}
	now := s.now()
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return nil, errf(KindInvalidParam, "waiver expiry must be a future time")
	}
	if strings.TrimSpace(approval.Approver) == "" {
		return nil, errf(KindInvalidParam, "waiver approver is required")
	}
	if approval.Time.IsZero() {
		approval.Time = now
	}
	// 幂等哈希只覆盖调用方提供的字段；Approval.Time 缺省由服务端填入当前时间，
	// 属于服务端元数据，不参与“同内容”判定（否则每次重放都会因时间不同而冲突）。
	hash := payloadHash(OpGrantWaiver, struct {
		Target   Version `json:"target"`
		Reason   string  `json:"reason"`
		Expires  int64   `json:"expires_unix_nano"`
		Approver string  `json:"approver"`
		Ticket   string  `json:"ticket"`
		Note     string  `json:"note"`
	}{target, quarantineReason, expiresAt.UTC().UnixNano(),
		approval.Approver, approval.Ticket, approval.Note})

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, conflict := s.lookupRequest(requestID, OpGrantWaiver, hash); conflict != nil {
		return nil, conflict
	} else if rec != nil {
		seq := mustAtoi(rec.Ref)
		return &WaiverGrantResult{Waiver: s.waivers[seq], Event: s.eventBySeq(seq), Replayed: true}, nil
	}

	pv, err := s.lookupVersion(target)
	if err != nil {
		return nil, err
	}
	qEvent, ok := s.active[pv.Version.key()][quarantineReason]
	if !ok {
		return nil, errf(KindConflict,
			"version %s has no active quarantine for reason %q; waiver can only cover an existing risk",
			pv.Version.key(), quarantineReason)
	}
	if cur := s.currentWaiver(qEvent.Seq, now); cur != nil {
		return nil, errf(KindConflict,
			"quarantine seq=%d already has an active waiver (waiver seq=%d, expires %s)",
			qEvent.Seq, cur.Seq, cur.ExpiresAt.Format(time.RFC3339))
	}

	seq := s.allocSeq()
	w := &RiskWaiver{
		Seq:           seq,
		QuarantineSeq: qEvent.Seq,
		Target:        pv.Version,
		Reason:        quarantineReason,
		GrantedAt:     now,
		ExpiresAt:     expiresAt.UTC(),
		Approval:      approval,
	}
	ev := s.eventAt(seq, OpGrantWaiver, pv.Version, requestID, quarantineReason, qEvent.Seq, now)
	rec := &requestRecord{ReqID: requestID, Op: OpGrantWaiver, Hash: hash, Ref: itoa(seq), CreatedAt: now}
	if err := s.persistWaiverGrant(ev, rec, w); err != nil {
		return nil, err
	}
	s.events = append(s.events, ev)
	s.requests[requestID] = rec
	s.waivers[seq] = w
	s.securityRev = ev.Rev
	return &WaiverGrantResult{Waiver: w, Event: ev}, nil
}

// RevokeWaiver 撤销针对 (target, quarantineReason) 当前有效（未撤销且未到期）的
// 豁免。成功后安全修订号加一。同号重放不重复生效。
func (s *Service) RevokeWaiver(requestID string, target Version, quarantineReason, note string) (*SecurityResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	if strings.TrimSpace(quarantineReason) == "" {
		return nil, errf(KindInvalidParam, "quarantine reason is required")
	}
	hash := payloadHash(OpRevokeWaiver, struct {
		Target Version `json:"target"`
		Reason string  `json:"reason"`
		Note   string  `json:"note"`
	}{target, quarantineReason, note})

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, conflict := s.lookupRequest(requestID, OpRevokeWaiver, hash); conflict != nil {
		return nil, conflict
	} else if rec != nil {
		return &SecurityResult{Event: s.eventBySeq(mustAtoi(rec.Ref)), Replayed: true}, nil
	}

	pv, err := s.lookupVersion(target)
	if err != nil {
		return nil, err
	}
	qEvent, ok := s.active[pv.Version.key()][quarantineReason]
	if !ok {
		return nil, errf(KindConflict,
			"version %s has no active quarantine for reason %q", pv.Version.key(), quarantineReason)
	}
	now := s.now()
	w := s.currentWaiver(qEvent.Seq, now)
	if w == nil {
		return nil, errf(KindConflict,
			"no active waiver for quarantine seq=%d (%s %q)",
			qEvent.Seq, pv.Version.key(), quarantineReason)
	}

	seq := s.allocSeq()
	ev := s.eventAt(seq, OpRevokeWaiver, pv.Version, requestID, note, w.Seq, now)
	rec := &requestRecord{ReqID: requestID, Op: OpRevokeWaiver, Hash: hash, Ref: itoa(seq), CreatedAt: now}

	w.RevokedAt = now
	w.RevokedReqID = requestID
	w.RevokeReason = note
	w.RevokeEventSeq = seq

	if err := s.persistWaiverRevoke(ev, rec, w); err != nil {
		return nil, err
	}
	s.events = append(s.events, ev)
	s.requests[requestID] = rec
	s.securityRev = ev.Rev
	return &SecurityResult{Event: ev}, nil
}

// currentWaiver 返回某条隔离当前有效的豁免（未撤销且在 now 时刻未到期），
// 没有则返回 nil。
func (s *Service) currentWaiver(quarantineSeq int, now time.Time) *RiskWaiver {
	var cur *RiskWaiver
	for _, w := range s.waivers {
		if w.QuarantineSeq != quarantineSeq || !w.RevokedAt.IsZero() {
			continue
		}
		if now.Before(w.ExpiresAt) && (cur == nil || w.Seq > cur.Seq) {
			cur = w
		}
	}
	return cur
}

// SecurityRev 返回当前安全修订号。
func (s *Service) SecurityRev() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.securityRev
}

// Snapshot 获取当前状态的不可变快照（含安全修订号、采样时刻、图、生效隔离与
// 该时刻有效的豁免）。一次解析/影响查询的全程只读取返回的这一份快照；采样在
// 持锁瞬间完成，期间任何发布、隔离、豁免或到期判定都不会影响它。
func (s *Service) Snapshot() *Snapshot {
	return s.snapshotAt(time.Now().UTC())
}

// snapshotAt 与 Snapshot 相同，但显式指定“当前时刻”，用于到期语义的确定性测试。
func (s *Service) snapshotAt(asOf time.Time) *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := &Snapshot{
		svc:      s,
		rev:      s.securityRev,
		asOf:     asOf,
		versions: make(map[string]*pkgVersion, len(s.versions)),
		active:   make(map[string]map[string]*SecurityEvent, len(s.active)),
		events:   make([]*SecurityEvent, len(s.events)),
		waived:   map[string]map[string]*RiskWaiver{},
	}
	for k, pv := range s.versions {
		snap.versions[k] = pv // pkgVersion 创建后不可变，可直接共享
	}
	for k, m := range s.active {
		cp := make(map[string]*SecurityEvent, len(m))
		for reason, ev := range m {
			e := *ev
			cp[reason] = &e
		}
		snap.active[k] = cp
	}
	for i, ev := range s.events {
		cp := *ev
		snap.events[i] = &cp
	}

	// 在与状态拷贝同一把锁、同一采样时刻下判定豁免有效性，杜绝 TOCTOU：
	// 撤销/到期/新增隔离与解析并发时，快照只会看到采样瞬间已提交的状态。
	for _, w0 := range s.waivers {
		if !w0.RevokedAt.IsZero() || !asOf.Before(w0.ExpiresAt) {
			continue
		}
		// 只收录其目标隔离仍以“同一条隔离事件”生效的豁免：豁免锁定的是隔离
		// 事件序号，旧隔离解除后即便用相同原因字符串重新隔离，旧豁免也不覆盖。
		m := snap.active[w0.Target.key()]
		if m == nil || m[w0.Reason] == nil || m[w0.Reason].Seq != w0.QuarantineSeq {
			continue
		}
		w := *w0
		if snap.waived[w.Target.key()] == nil {
			snap.waived[w.Target.key()] = map[string]*RiskWaiver{}
		}
		// 同一 (版本,原因) 同一时刻至多一条有效豁免；防御性地保留序号更大者。
		if old := snap.waived[w.Target.key()][w.Reason]; old == nil || w.Seq > old.Seq {
			snap.waived[w.Target.key()][w.Reason] = &w
		}
	}
	return snap
}

// Snapshot 是某一时刻的只读视图。
type Snapshot struct {
	svc      *Service
	rev      int
	asOf     time.Time
	versions map[string]*pkgVersion
	active   map[string]map[string]*SecurityEvent
	events   []*SecurityEvent

	// 采样时刻有效、且目标隔离仍生效的豁免：版本键 -> 隔离原因 -> 豁免。
	waived map[string]map[string]*RiskWaiver
}

// Rev 返回该快照的安全修订号。
func (snap *Snapshot) Rev() int { return snap.rev }

// AsOf 返回该快照采样“当前时刻”的时间点（豁免到期判定基准）。
func (snap *Snapshot) AsOf() time.Time { return snap.asOf }

// Resolution 是成功解析的结果。
type Resolution struct {
	Rev      int         // 解析所基于的安全修订快照
	Root     Version     // 解析起点
	Versions []Version   // 需要安装的全部版本（根 + 所有传递依赖），按 key 排序去重
	Waivers  []WaiverUse // 本次解析实际采用的豁免（闭包内触及的被豁免风险），按 (target, reason) 排序
}

// WaiverUse 说明一次解析为何可以采用某条豁免：精确到被豁免的版本、隔离原因、
// 隔离/豁免事件序号，以及从解析根到该版本的依赖路径与批准/有效期信息。
type WaiverUse struct {
	Target        Version   `json:"target"`
	Reason        string    `json:"reason"`
	QuarantineSeq int       `json:"quarantine_seq"`
	WaiverSeq     int       `json:"waiver_seq"`
	Path          []Version `json:"path"`
	GrantedAt     time.Time `json:"granted_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Approval      Approval  `json:"approval"`
}

// WaiverUsageRecord 是一次解析采用豁免的留痕。
type WaiverUsageRecord struct {
	Time time.Time   `json:"time"`
	Rev  int         `json:"rev"`
	Root Version     `json:"root"`
	Uses []WaiverUse `json:"uses"`
}

// BlockedError 表示根版本在当前快照下被隔离规则排除。
// Path 给出可解释的依赖路径：根版本 → … → 被直接隔离的版本；
// Reason 是终点上实际造成阻塞的那条隔离原因（未被豁免覆盖的原因）。
type BlockedError struct {
	Rev         int
	Path        []Version
	Quarantined Version
	Reason      string
	Cause       *Error
}

func (e *BlockedError) Error() string { return e.Cause.Error() }
func (e *BlockedError) Unwrap() error { return e.Cause }

// taintHit 是污染分析命中：从某版本沿依赖边到某个“存在未被豁免的隔离原因”的
// 版本的路径（不含起点自身的键），以及终点上造成阻塞的那条原因。
type taintHit struct {
	path   []string
	reason string
}

// Resolve 在该快照上做安装解析：返回根版本及其全部传递依赖。
// 若根版本被（未豁免的原因）直接隔离，或其任一传递依赖如此，则返回
// *BlockedError，其中带有一条从根到被隔离版本的依赖路径与阻塞原因。
//
// 解析全程只读取该快照：采样之后发生的隔离、豁免授予/撤销只影响下一次请求；
// 豁免只放开它精确关联的那一条 (版本, 原因) 风险，同一版本的其它风险原因
// 仍然阻塞解析。成功解析若采用了豁免，会记录一条 WaiverUsageRecord 留痕。
func (snap *Snapshot) Resolve(name, version string) (*Resolution, error) {
	k := name + "@" + version
	root, ok := snap.versions[k]
	if !ok {
		return nil, errf(KindNotFound, "version %s does not exist", k)
	}

	tainted := snap.taintMap()
	if hit := tainted[k]; hit != nil {
		path := make([]Version, 0, len(hit.path)+1)
		path = append(path, root.Version)
		for _, dk := range hit.path {
			path = append(path, snap.versions[dk].Version)
		}
		return nil, &BlockedError{
			Rev:         snap.rev,
			Path:        path,
			Quarantined: path[len(path)-1],
			Reason:      hit.reason,
			Cause: errf(KindDependency,
				"resolution blocked by quarantine reason %q: %s", hit.reason, formatPath(path)),
		}
	}

	// 根未被污染：收集闭包，同时记录闭包内每个被豁免版本的采用路径与原因。
	collected := map[string]Version{k: root.Version}
	var uses []WaiverUse
	seen := map[string]bool{}

	var walk func(pv *pkgVersion, stack []Version)
	walk = func(pv *pkgVersion, stack []Version) {
		for reason, w := range snap.waived[pv.Version.key()] {
			qev := snap.active[pv.Version.key()][reason]
			uses = append(uses, WaiverUse{
				Target:        pv.Version,
				Reason:        reason,
				QuarantineSeq: qev.Seq,
				WaiverSeq:     w.Seq,
				Path:          append([]Version(nil), stack...),
				GrantedAt:     w.GrantedAt,
				ExpiresAt:     w.ExpiresAt,
				Approval:      w.Approval,
			})
		}
		for _, d := range pv.Deps {
			if seen[d.key()] {
				continue
			}
			seen[d.key()] = true
			collected[d.key()] = d
			walk(snap.versions[d.key()], append(append([]Version{}, stack...), d))
		}
	}
	seen[k] = true
	walk(root, []Version{root.Version})

	out := make([]Version, 0, len(collected))
	for _, v := range collected {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	sort.Slice(uses, func(i, j int) bool {
		if uses[i].Target.key() != uses[j].Target.key() {
			return uses[i].Target.key() < uses[j].Target.key()
		}
		return uses[i].Reason < uses[j].Reason
	})

	res := &Resolution{Rev: snap.rev, Root: root.Version, Versions: out, Waivers: uses}
	if len(uses) > 0 && snap.svc != nil {
		snap.svc.recordWaiverUsage(root.Version, snap.rev, uses)
	}
	return res, nil
}

// recordWaiverUsage 将一次解析采用豁免的原因落为留痕。该方法不推进安全修订号
// （留痕不是安全状态变更），但与状态变更一样经同一把互斥锁串行化。
func (s *Service) recordWaiverUsage(root Version, rev int, uses []WaiverUse) {
	rec := WaiverUsageRecord{
		Time: time.Now().UTC(),
		Rev:  rev,
		Root: root,
		Uses: append([]WaiverUse(nil), uses...),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waiverUsage = append(s.waiverUsage, rec)
	if s.store != nil {
		_ = s.store.appendWaiverUsage(&rec) // 留痕落盘失败不改变解析结果
	}
}

// WaiverUsage 返回全部解析采用豁免的留痕（按记录顺序的防御性拷贝）。
func (s *Service) WaiverUsage() []WaiverUsageRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]WaiverUsageRecord, len(s.waiverUsage))
	for i, r := range s.waiverUsage {
		out[i] = cloneUsageRecord(r)
	}
	return out
}

func cloneUsageRecord(r WaiverUsageRecord) WaiverUsageRecord {
	cp := r
	cp.Uses = make([]WaiverUse, len(r.Uses))
	for i, u := range r.Uses {
		u.Path = append([]Version(nil), u.Path...)
		cp.Uses[i] = u
	}
	return cp
}

// QuarantineStatus 描述目标版本上某一条原因隔离及其豁免状态。
type QuarantineStatus struct {
	Reason          string    // 隔离原因
	EventSeq        int       // 隔离事件序号
	Waived          bool      // 采样时刻该条风险是否被有效豁免覆盖
	WaiverSeq       int       // 豁免事件序号；未豁免为 0
	WaiverExpiresAt time.Time // 豁免到期时间
	WaiverApprover  string    // 豁免批准人
}

// ImpactEntry 描述受目标版本影响的一个（传递）依赖方。
type ImpactEntry struct {
	Version Version   // 受影响的依赖方版本
	Path    []Version // 依赖路径：依赖方 → … → 目标版本
	Blocked bool      // 在当前快照下该依赖方是否处于被排除状态
}

// ImpactReport 是影响查询结果。
type ImpactReport struct {
	Rev                 int
	Target              Version
	DirectlyQuarantined bool // 目标版本当前是否存在任意原因的生效隔离（含已被豁免覆盖的）
	QuarantineEventSeq  int  // 最早一条生效隔离的事件序号；无隔离为 0
	Quarantines         []QuarantineStatus
	Affected            []ImpactEntry // 所有（传递）依赖到目标版本的版本，按 key 排序
}

// Impact 在该快照上查询影响：谁（传递）依赖了目标版本、各自的依赖路径，
// 以及它们在当前安全修订下是否被排除。目标版本不存在返回 KindNotFound。
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

	tainted := snap.taintMap()

	report := &ImpactReport{Rev: snap.rev, Target: target.Version}
	if m := snap.active[k]; len(m) > 0 {
		report.DirectlyQuarantined = true
		reasons := make([]string, 0, len(m))
		for reason := range m {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			ev := m[reason]
			if report.QuarantineEventSeq == 0 || ev.Seq < report.QuarantineEventSeq {
				report.QuarantineEventSeq = ev.Seq
			}
			st := QuarantineStatus{Reason: reason, EventSeq: ev.Seq}
			if w := snap.waived[k][reason]; w != nil {
				st.Waived = true
				st.WaiverSeq = w.Seq
				st.WaiverExpiresAt = w.ExpiresAt
				st.WaiverApprover = w.Approval.Approver
			}
			report.Quarantines = append(report.Quarantines, st)
		}
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

// AuditEvents 返回截至该快照的审计历史（按事件序号排序）。
func (snap *Snapshot) AuditEvents() []*SecurityEvent {
	out := make([]*SecurityEvent, len(snap.events))
	for i, ev := range snap.events {
		cp := *ev
		out[i] = &cp
	}
	return out
}

// ActiveWaivers 返回该快照采样时刻有效的豁免（防御性拷贝，按 target、reason 排序）。
func (snap *Snapshot) ActiveWaivers() []RiskWaiver {
	var out []RiskWaiver
	for _, m := range snap.waived {
		for _, w := range m {
			out = append(out, *w)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target.key() != out[j].Target.key() {
			return out[i].Target.key() < out[j].Target.key()
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// taintMap 计算污染分析：对每个版本，若它本身存在未被豁免覆盖的隔离原因、
// 或沿依赖边可达这样的版本，则记录从该版本到某个阻塞版本的键路径与阻塞原因。
// 返回 nil 表示该版本在当前快照下未被污染。
// 图是发布时保证的 DAG，故 memo DFS 必然终止；多条路径时取依赖声明顺序
// 最先发现的一条，自身多原因时按原因字典序取第一条，保证结果稳定可解释。
func (snap *Snapshot) taintMap() map[string]*taintHit {
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

		// 1) 自身：未被有效豁免覆盖的隔离原因构成阻塞。
		if qs := snap.active[k]; len(qs) > 0 {
			open := make([]string, 0, len(qs))
			for reason := range qs {
				if snap.waived[k][reason] == nil {
					open = append(open, reason)
				}
			}
			sort.Strings(open)
			if len(open) > 0 {
				hit = &taintHit{path: []string{}, reason: open[0]}
			}
		}

		// 2) 依赖：声明顺序优先，取第一个仍被阻塞的下游。
		if hit == nil {
			pv := snap.versions[k]
			for _, d := range pv.Deps {
				dk := d.key()
				child := visit(dk)
				if child != nil {
					hit = &taintHit{
						path:   append([]string{dk}, child.path...),
						reason: child.reason,
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

// ---- 内部辅助 ----

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

// allocSeq 分配下一个全局事件序号（调用方须持锁）。
func (s *Service) allocSeq() int {
	s.nextSeq++
	return s.nextSeq
}

func (s *Service) newEvent(kind string, target Version, reqID, reason string, related int) *SecurityEvent {
	return s.eventAt(s.allocSeq(), kind, target, reqID, reason, related, s.now())
}

// eventAt 用给定序号与时间构造事件，Rev 按“应用序号 = 当前修订 +1”计算。
func (s *Service) eventAt(seq int, kind string, target Version, reqID, reason string, related int, now time.Time) *SecurityEvent {
	return &SecurityEvent{
		Seq:        seq,
		Rev:        s.securityRev + 1,
		Kind:       kind,
		Target:     target,
		ReqID:      reqID,
		Reason:     reason,
		RelatedSeq: related,
		Time:       now,
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

func (s *Service) persistWaiverGrant(ev *SecurityEvent, rec *requestRecord, w *RiskWaiver) error {
	if s.store == nil {
		return nil
	}
	if err := s.store.appendAudit(ev); err != nil {
		return err
	}
	if err := s.store.appendWaiver(w); err != nil {
		return err
	}
	return s.store.appendRequests(rec)
}

func (s *Service) persistWaiverRevoke(ev *SecurityEvent, rec *requestRecord, w *RiskWaiver) error {
	if s.store == nil {
		return nil
	}
	if err := s.store.appendAudit(ev); err != nil {
		return err
	}
	if err := s.store.appendWaiver(w); err != nil {
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
