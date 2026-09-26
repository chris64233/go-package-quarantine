// Package packagequarantine 实现会沿依赖图传播的软件包版本隔离服务。
//
// 核心模型：
//   - 软件包版本由 (名称, 版本号, 内容摘要) 唯一确定，发布后不可变；
//   - 发布时保存解析后的直接依赖，依赖不存在或构成环都会导致发布失败；
//   - 安全事件隔离某一具体版本，隔离效果沿依赖图正向传播：任何（传递）依赖到
//     被隔离版本的版本都会在安装解析中被排除；
//   - 每次隔离/解除都使安全修订号 +1，解析在进入时获取一份不可变快照，
//     全程只读取该快照；
//   - 发布、隔离、解除均要求携带外部请求号实现幂等，同号异内容返回冲突。
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
	Op        string    `json:"op"` // publish | quarantine | release
	Hash      string    `json:"hash"`
	Ref       string    `json:"ref"` // publish: 版本键；隔离/解除: 事件序号
	CreatedAt time.Time `json:"created_at"`
}

// 安全事件类型。
const (
	OpQuarantine = "quarantine"
	OpRelease    = "release"
)

// SecurityEvent 是一条审计历史：隔离或解除事件。
type SecurityEvent struct {
	Seq        int       `json:"seq"`         // 全局单调递增的事件序号
	Rev        int       `json:"rev"`         // 应用该事件后的安全修订号
	Kind       string    `json:"kind"`        // quarantine | release
	Target     Version   `json:"target"`      // 被操作的具体版本
	ReqID      string    `json:"req_id"`      // 外部请求号
	Reason     string    `json:"reason"`      // 备注（可选）
	RelatedSeq int       `json:"related_seq"` // release 事件所解除的 quarantine 事件序号
	Time       time.Time `json:"time"`
}

// Service 是软件包隔离服务。零值不可用，请使用 NewService 创建。
type Service struct {
	mu sync.RWMutex

	store *store // 持久化句柄；nil 表示纯内存模式

	versions map[string]*pkgVersion // key(name@version) -> 版本
	requests map[string]*requestRecord
	events   []*SecurityEvent          // 按 Seq 排序的完整审计历史
	active   map[string]*SecurityEvent // 当前生效的隔离：版本键 -> quarantine 事件

	securityRev int // 当前安全修订号
	nextSeq     int // 下一个事件序号
}

// NewService 创建服务。dir 为空时使用纯内存模式；否则在 dir 下以 JSONL 持久化
// 图关系（graph.jsonl）、幂等请求（requests.jsonl）与审计历史（audit.jsonl），
// 目录已存在数据时会自动重建状态。
func NewService(dir string) (*Service, error) {
	s := &Service{
		versions: map[string]*pkgVersion{},
		requests: map[string]*requestRecord{},
		active:   map[string]*SecurityEvent{},
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
		PublishedAt:  time.Now().UTC(),
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

// Quarantine 隔离某一具体版本。版本必须已发布。
// 若该版本当前已有生效隔离（来自不同请求号），返回 KindConflict。
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
	if ev, ok := s.active[pv.Version.key()]; ok {
		return nil, errf(KindConflict,
			"version %s is already quarantined by event seq=%d", pv.Version.key(), ev.Seq)
	}

	ev := s.newEvent(OpQuarantine, pv.Version, requestID, reason, 0)
	rec := s.newRequestRecord(requestID, OpQuarantine, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	s.active[pv.Version.key()] = ev
	return &SecurityResult{Event: ev}, nil
}

// Release 解除目标版本上当前生效的隔离。成功后安全修订号加一。
//
// 解除只移除指向该版本的那一条隔离；如果它（或其它版本）仍被其它生效隔离
// 沿依赖路径影响，解析结果不会因此恢复。
func (s *Service) Release(requestID string, target Version, reason string) (*SecurityResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	hash := payloadHash(OpRelease, struct {
		Target Version `json:"target"`
		Reason string  `json:"reason"`
	}{target, reason})

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
	qEvent, ok := s.active[pv.Version.key()]
	if !ok {
		return nil, errf(KindConflict, "version %s has no active quarantine", pv.Version.key())
	}

	ev := s.newEvent(OpRelease, pv.Version, requestID, reason, qEvent.Seq)
	rec := s.newRequestRecord(requestID, OpRelease, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	delete(s.active, pv.Version.key())
	return &SecurityResult{Event: ev}, nil
}

// SecurityRev 返回当前安全修订号。
func (s *Service) SecurityRev() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.securityRev
}

// Snapshot 获取当前状态的不可变快照（含安全修订号、图与生效隔离）。
// 一次解析/影响查询的全程只读取返回的这一份快照，期间任何发布或安全操作
// 都不会影响它。
func (s *Service) Snapshot() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := &Snapshot{
		rev:      s.securityRev,
		versions: make(map[string]*pkgVersion, len(s.versions)),
		active:   make(map[string]*SecurityEvent, len(s.active)),
		events:   make([]*SecurityEvent, len(s.events)),
	}
	for k, pv := range s.versions {
		snap.versions[k] = pv // pkgVersion 创建后不可变，可直接共享
	}
	for k, ev := range s.active {
		cp := *ev
		snap.active[k] = &cp
	}
	for i, ev := range s.events {
		cp := *ev
		snap.events[i] = &cp
	}
	return snap
}

// Snapshot 是某一时刻的只读视图。
type Snapshot struct {
	rev      int
	versions map[string]*pkgVersion
	active   map[string]*SecurityEvent
	events   []*SecurityEvent
}

// Rev 返回该快照的安全修订号。
func (snap *Snapshot) Rev() int { return snap.rev }

// Resolution 是成功解析的结果。
type Resolution struct {
	Rev      int       // 解析所基于的安全修订快照
	Root     Version   // 解析起点
	Versions []Version // 需要安装的全部版本（根 + 所有传递依赖），按 key 排序去重
}

// BlockedError 表示根版本在当前快照下被隔离规则排除。
// Path 给出可解释的依赖路径：根版本 → … → 被直接隔离的版本。
type BlockedError struct {
	Rev         int
	Path        []Version
	Quarantined Version
	Cause       *Error
}

func (e *BlockedError) Error() string { return e.Cause.Error() }
func (e *BlockedError) Unwrap() error { return e.Cause }

// Resolve 在该快照上做安装解析：返回根版本及其全部传递依赖。
// 若根版本被直接隔离，或其任一传递依赖被隔离，则返回 *BlockedError，
// 其中带有一条从根到被隔离版本的依赖路径。
func (snap *Snapshot) Resolve(name, version string) (*Resolution, error) {
	k := name + "@" + version
	root, ok := snap.versions[k]
	if !ok {
		return nil, errf(KindNotFound, "version %s does not exist", k)
	}

	tainted := snap.taintMap()
	if hit := tainted[k]; hit != nil {
		path := make([]Version, 0, len(hit)+1)
		path = append(path, root.Version)
		for _, dk := range hit {
			path = append(path, snap.versions[dk].Version)
		}
		return nil, &BlockedError{
			Rev:         snap.rev,
			Path:        path,
			Quarantined: path[len(path)-1],
			Cause:       errf(KindDependency, "resolution blocked by quarantine: %s", formatPath(path)),
		}
	}

	// 根未被污染，其整条依赖闭包都不会触及被隔离版本（上面的污染分析已覆盖）。
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
	return &Resolution{Rev: snap.rev, Root: root.Version, Versions: out}, nil
}

// ImpactEntry 描述受目标版本影响的一个（传递）依赖方。
type ImpactEntry struct {
	Version Version   // 受影响的依赖方版本
	Path    []Version // 依赖路径：依赖方 → … → 目标版本
	Blocked bool      // 在当前快照下该依赖方是否处于被排除状态（可能经由其它隔离路径）
}

// ImpactReport 是影响查询结果。
type ImpactReport struct {
	Rev                 int
	Target              Version
	DirectlyQuarantined bool          // 目标版本当前是否被直接隔离
	QuarantineEventSeq  int           // 生效隔离事件序号；未隔离为 0
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
	if ev, ok := snap.active[k]; ok {
		report.DirectlyQuarantined = true
		report.QuarantineEventSeq = ev.Seq
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

// taintMap 计算污染分析：对每个版本，若它本身被直接隔离、或沿依赖边可达
// 任一被直接隔离版本，则记录从该版本到某个被隔离版本的键路径（含自身之后
// 的节点，不含自身）。返回 nil 表示该版本未被污染。
// 图是发布时保证的 DAG，故 memo DFS 必然终止；多条路径时取依赖声明顺序
// 最先发现的一条，保证结果稳定可解释。
func (snap *Snapshot) taintMap() map[string][]string {
	type state int
	const (
		visiting state = iota
		done
	)
	color := map[string]state{}
	memo := map[string][]string{} // nil = 未污染

	var visit func(k string) []string
	visit = func(k string) []string {
		if color[k] == done {
			return memo[k]
		}
		color[k] = visiting
		var suffix []string
		if _, direct := snap.active[k]; direct {
			suffix = []string{} // 终点：自身之后无节点
		} else {
			pv := snap.versions[k]
			for _, d := range pv.Deps {
				dk := d.key()
				child := visit(dk)
				if child != nil {
					suffix = append([]string{dk}, child...)
					break
				}
			}
		}
		color[k] = done
		memo[k] = suffix
		return suffix
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

func (s *Service) newEvent(kind string, target Version, reqID, reason string, related int) *SecurityEvent {
	s.nextSeq++
	return &SecurityEvent{
		Seq:        s.nextSeq,
		Rev:        s.securityRev + 1,
		Kind:       kind,
		Target:     target,
		ReqID:      reqID,
		Reason:     reason,
		RelatedSeq: related,
		Time:       time.Now().UTC(),
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
