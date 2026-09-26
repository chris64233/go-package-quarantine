package packagequarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const digestPrefix = "sha256:"

// Service 软件包版本隔离服务。所有方法可并发调用：
// 发布、隔离、解除互斥串行化，解析在安全修订号对应的快照上执行。
type Service struct {
	mu   sync.RWMutex
	path string // 持久化文件路径；为空则仅内存
	st   *state
}

type state struct {
	packages    map[PackageID]*PackageVersion
	byName      map[string][]PackageID          // 每个名称下的版本坐标，按版本号降序
	byNameVer   map[string]map[string]PackageID // 名称 -> 版本号 -> 坐标
	quarantines map[string]*QuarantineRecord
	requests    map[string]*idemRecord // 外部请求号 -> 幂等记录
	audit       []AuditEntry
	secRevision uint64 // 安全修订号：每次隔离/解除递增
	seq         uint64 // 全局序号：版本序号、隔离单号、审计序号
}

// idemRecord 幂等记录：保存请求指纹与首次执行的结果，用于重放与冲突检测。
type idemRecord struct {
	Op          string            `json:"op"`
	Fingerprint string            `json:"fingerprint"`
	Published   *PackageVersion   `json:"published,omitempty"`
	Quarantine  *QuarantineRecord `json:"quarantine,omitempty"`
}

// NewService 创建服务；path 非空时从该文件加载并在每次变更后持久化。
func NewService(path string) (*Service, error) {
	s := &Service{path: path, st: newState()}
	if path != "" {
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func newState() *state {
	return &state{
		packages:    map[PackageID]*PackageVersion{},
		byName:      map[string][]PackageID{},
		byNameVer:   map[string]map[string]PackageID{},
		quarantines: map[string]*QuarantineRecord{},
		requests:    map[string]*idemRecord{},
	}
}

// PublishRequest 版本发布请求。RequestID 为外部请求号，保证幂等。
type PublishRequest struct {
	RequestID string
	Name      string
	Version   string
	Digest    string
	Deps      []DepSpec
}

// Publish 发布一个不可变的版本。依赖必须已发布且未被隔离；
// 依赖缺失、依赖成环或依赖被隔离都会使发布失败。
func (s *Service) Publish(req PublishRequest) (*PackageVersion, error) {
	if req.RequestID == "" {
		return nil, newError(ErrKindParam, "外部请求号不能为空")
	}
	if req.Name == "" {
		return nil, newError(ErrKindParam, "软件包名称不能为空")
	}
	if !validVersion(req.Version) {
		return nil, newError(ErrKindParam, "版本号 %q 非法，应为 X.Y.Z 数字格式", req.Version)
	}
	if err := validateDigest(req.Digest); err != nil {
		return nil, err
	}
	seen := map[DepSpec]bool{}
	for _, d := range req.Deps {
		if d.Name == "" {
			return nil, newError(ErrKindParam, "依赖名称不能为空")
		}
		if !validVersion(d.Version) {
			return nil, newError(ErrKindParam, "依赖 %s 的版本号 %q 非法", d.Name, d.Version)
		}
		if seen[d] {
			return nil, newError(ErrKindParam, "依赖 %s@%s 重复声明", d.Name, d.Version)
		}
		seen[d] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fp := fingerprint("publish", canonicalPublish(req))
	if rec, ok := s.st.requests[req.RequestID]; ok {
		if rec.Op != "publish" || rec.Fingerprint != fp {
			return nil, newError(ErrKindIdempotency, "请求号 %q 已以不同内容执行过", req.RequestID)
		}
		pv := *rec.Published
		return &pv, nil
	}

	// 同名同版本已发布：摘要不同则违反不可变性；完全相同则视为安全重试。
	if existingID, ok := s.st.byNameVer[req.Name][req.Version]; ok {
		if existingID.Digest != req.Digest {
			return nil, newError(ErrKindDigest,
				"版本 %s@%s 已发布（摘要 %s），内容摘要不可更改", req.Name, req.Version, existingID.Digest)
		}
		pv := s.st.packages[existingID]
		s.st.requests[req.RequestID] = &idemRecord{Op: "publish", Fingerprint: fp, Published: pv}
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
		out := *pv
		return &out, nil
	}

	// 解析直接依赖为确切坐标。
	deps := make([]PackageID, 0, len(req.Deps))
	for _, d := range req.Deps {
		id, ok := s.st.byNameVer[d.Name][d.Version]
		if !ok {
			return nil, newError(ErrKindDependency, "依赖 %s@%s 不存在", d.Name, d.Version)
		}
		deps = append(deps, id)
	}

	self := PackageID{Name: req.Name, Version: req.Version, Digest: req.Digest}
	if err := s.checkCycleLocked(self, deps); err != nil {
		return nil, err
	}

	// 已确认的隔离不能被迟到发布绕开：在同一把写锁内校验依赖未被隔离波及。
	affected := s.affectedLocked(s.activeQuarantinesLocked())
	for _, d := range deps {
		if ex, bad := affected[d]; bad {
			return nil, newError(ErrKindDependency,
				"依赖 %s 被隔离单 %s 排除，路径: %s", d, ex.QuarantineID, formatPath(ex.Path))
		}
	}

	s.st.seq++
	pv := &PackageVersion{ID: self, Deps: deps, PublishedAt: time.Now().UTC(), Seq: s.st.seq}
	s.st.packages[pv.ID] = pv
	if s.st.byNameVer[pv.ID.Name] == nil {
		s.st.byNameVer[pv.ID.Name] = map[string]PackageID{}
	}
	s.st.byNameVer[pv.ID.Name][pv.ID.Version] = pv.ID
	s.st.byName[pv.ID.Name] = append(s.st.byName[pv.ID.Name], pv.ID)
	sortVersionsDesc(s.st.byName[pv.ID.Name])

	s.st.requests[req.RequestID] = &idemRecord{Op: "publish", Fingerprint: fp, Published: pv}
	s.appendAuditLocked("publish", req.RequestID, fmt.Sprintf("发布 %s", pv.ID))
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	out := *pv
	return &out, nil
}

// QuarantineRequest 隔离请求。
type QuarantineRequest struct {
	RequestID string
	Target    PackageID
	Reason    string
}

// Quarantine 隔离某一具体版本，安全修订号递增。
// 同一版本允许存在多条生效中的隔离记录。
func (s *Service) Quarantine(req QuarantineRequest) (*QuarantineRecord, error) {
	if req.RequestID == "" {
		return nil, newError(ErrKindParam, "外部请求号不能为空")
	}
	if req.Target.Name == "" || req.Target.Version == "" {
		return nil, newError(ErrKindParam, "隔离目标的名称与版本号不能为空")
	}
	if err := validateDigest(req.Target.Digest); err != nil {
		return nil, err
	}
	if req.Reason == "" {
		return nil, newError(ErrKindParam, "隔离原因不能为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fp := fingerprint("quarantine", req)
	if rec, ok := s.st.requests[req.RequestID]; ok {
		if rec.Op != "quarantine" || rec.Fingerprint != fp {
			return nil, newError(ErrKindIdempotency, "请求号 %q 已以不同内容执行过", req.RequestID)
		}
		out := *rec.Quarantine
		return &out, nil
	}

	if _, ok := s.st.packages[req.Target]; !ok {
		return nil, newError(ErrKindNotFound, "版本 %s 不存在", req.Target)
	}

	s.st.seq++
	rec := &QuarantineRecord{
		ID:        fmt.Sprintf("Q-%d", s.st.seq),
		Target:    req.Target,
		Reason:    req.Reason,
		Active:    true,
		CreatedAt: time.Now().UTC(),
	}
	s.st.quarantines[rec.ID] = rec
	s.st.secRevision++
	s.st.requests[req.RequestID] = &idemRecord{Op: "quarantine", Fingerprint: fp, Quarantine: rec}
	s.appendAuditLocked("quarantine", req.RequestID,
		fmt.Sprintf("隔离 %s（单号 %s）：%s", rec.Target, rec.ID, rec.Reason))
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	out := *rec
	return &out, nil
}

// LiftRequest 解除隔离请求，按隔离单号解除。
type LiftRequest struct {
	RequestID    string
	QuarantineID string
}

// LiftQuarantine 解除一条隔离记录，安全修订号递增。
// 仍被其他生效隔离路径影响的版本不会因此恢复。
func (s *Service) LiftQuarantine(req LiftRequest) (*QuarantineRecord, error) {
	if req.RequestID == "" {
		return nil, newError(ErrKindParam, "外部请求号不能为空")
	}
	if req.QuarantineID == "" {
		return nil, newError(ErrKindParam, "隔离单号不能为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fp := fingerprint("lift", req)
	if rec, ok := s.st.requests[req.RequestID]; ok {
		if rec.Op != "lift" || rec.Fingerprint != fp {
			return nil, newError(ErrKindIdempotency, "请求号 %q 已以不同内容执行过", req.RequestID)
		}
		out := *rec.Quarantine
		return &out, nil
	}

	rec, ok := s.st.quarantines[req.QuarantineID]
	if !ok {
		return nil, newError(ErrKindNotFound, "隔离单 %q 不存在", req.QuarantineID)
	}
	if !rec.Active {
		return nil, newError(ErrKindState, "隔离单 %q 已解除", req.QuarantineID)
	}

	now := time.Now().UTC()
	rec.Active = false
	rec.LiftedAt = &now
	s.st.secRevision++
	s.st.requests[req.RequestID] = &idemRecord{Op: "lift", Fingerprint: fp, Quarantine: rec}
	s.appendAuditLocked("lift", req.RequestID,
		fmt.Sprintf("解除隔离单 %s（目标 %s）", rec.ID, rec.Target))
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	out := *rec
	return &out, nil
}

// Resolve 解析指定名称的安装版本：选择未被隔离波及的最高版本。
// 被排除的候选版本附带可解释的依赖路径。整个解析读取同一安全修订快照。
func (s *Service) Resolve(name string) (*Resolution, error) {
	if name == "" {
		return nil, newError(ErrKindParam, "软件包名称不能为空")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.st.byName[name]
	if len(ids) == 0 {
		return nil, newError(ErrKindNotFound, "软件包 %q 不存在任何已发布版本", name)
	}

	res := &Resolution{Name: name, SecurityRevision: s.st.secRevision}
	affected := s.affectedLocked(s.activeQuarantinesLocked())
	for _, id := range ids {
		if ex, bad := affected[id]; bad {
			res.Excluded = append(res.Excluded, ex)
			continue
		}
		if res.Selected == nil {
			pv := *s.st.packages[id]
			res.Selected = &pv
			res.Closure = s.closureLocked(pv.ID)
		}
	}
	return res, nil
}

// Impact 影响查询：返回针对某版本的生效隔离记录，以及沿依赖图被波及的版本。
func (s *Service) Impact(target PackageID) (*ImpactReport, error) {
	if target.Name == "" || target.Version == "" {
		return nil, newError(ErrKindParam, "目标的名称与版本号不能为空")
	}
	if err := validateDigest(target.Digest); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.st.packages[target]; !ok {
		return nil, newError(ErrKindNotFound, "版本 %s 不存在", target)
	}

	var recs []*QuarantineRecord
	for _, q := range s.st.quarantines {
		if q.Active && q.Target == target {
			recs = append(recs, q)
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ID < recs[j].ID })

	report := &ImpactReport{Target: target}
	affected := s.affectedLocked(recs)
	for _, q := range recs {
		report.Quarantines = append(report.Quarantines, *q)
	}
	for _, ex := range affected {
		report.Affected = append(report.Affected, ex)
	}
	sort.Slice(report.Affected, func(i, j int) bool {
		return report.Affected[i].Package.String() < report.Affected[j].Package.String()
	})
	return report, nil
}

// SecurityRevision 返回当前安全修订号。
func (s *Service) SecurityRevision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.secRevision
}

// AuditLog 返回审计历史的副本。
func (s *Service) AuditLog() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEntry, len(s.st.audit))
	copy(out, s.st.audit)
	return out
}

// activeQuarantinesLocked 返回全部生效中的隔离记录（按单号排序，保证遍历确定）。
func (s *Service) activeQuarantinesLocked() []*QuarantineRecord {
	var recs []*QuarantineRecord
	for _, q := range s.st.quarantines {
		if q.Active {
			recs = append(recs, q)
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ID < recs[j].ID })
	return recs
}

// affectedLocked 计算被给定隔离记录波及的版本集合：
// 从隔离目标沿反向依赖边向上传播，值为首个到达的见证路径。
func (s *Service) affectedLocked(recs []*QuarantineRecord) map[PackageID]Exclusion {
	// 反向依赖图：被依赖者 -> 依赖它的版本。
	dependents := map[PackageID][]PackageID{}
	for _, pv := range s.st.packages {
		for _, d := range pv.Deps {
			dependents[d] = append(dependents[d], pv.ID)
		}
	}
	for _, list := range dependents {
		sort.Slice(list, func(i, j int) bool { return list[i].String() < list[j].String() })
	}

	out := map[PackageID]Exclusion{}
	for _, q := range recs {
		if q == nil || !q.Active {
			continue
		}
		type item struct {
			id   PackageID
			path []PackageID // 从隔离目标到当前版本
		}
		visited := map[PackageID]bool{q.Target: true}
		queue := []item{{q.Target, []PackageID{q.Target}}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if _, ok := out[cur.id]; !ok {
				// 反转为“从被排除版本到隔离目标”的解释路径。
				path := make([]PackageID, len(cur.path))
				for i, p := range cur.path {
					path[len(cur.path)-1-i] = p
				}
				out[cur.id] = Exclusion{
					Package:      cur.id,
					QuarantineID: q.ID,
					Reason:       q.Reason,
					Path:         path,
				}
			}
			for _, dep := range dependents[cur.id] {
				if visited[dep] {
					continue
				}
				visited[dep] = true
				next := append(append([]PackageID{}, cur.path...), dep)
				queue = append(queue, item{dep, next})
			}
		}
	}
	return out
}

// checkCycleLocked 检测以新版本为起点的依赖环。
func (s *Service) checkCycleLocked(self PackageID, deps []PackageID) error {
	visited := map[PackageID]bool{}
	var visit func(id PackageID) []PackageID // 返回到达 self 的路径，未到达返回 nil
	visit = func(id PackageID) []PackageID {
		if id == self {
			return []PackageID{id}
		}
		if visited[id] {
			return nil
		}
		visited[id] = true
		pv := s.st.packages[id]
		if pv == nil {
			return nil
		}
		for _, d := range pv.Deps {
			if tail := visit(d); tail != nil {
				return append([]PackageID{id}, tail...)
			}
		}
		return nil
	}
	for _, d := range deps {
		if path := visit(d); path != nil {
			return newError(ErrKindDependency, "依赖环: %s -> %s", self, formatPath(path))
		}
	}
	return nil
}

// closureLocked 计算版本的传递依赖闭包（不含自身），按坐标排序。
func (s *Service) closureLocked(root PackageID) []PackageID {
	seen := map[PackageID]bool{root: true}
	var out []PackageID
	queue := append([]PackageID{}, s.st.packages[root].Deps...)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		if pv := s.st.packages[id]; pv != nil {
			queue = append(queue, pv.Deps...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (s *Service) appendAuditLocked(op, requestID, detail string) {
	s.st.audit = append(s.st.audit, AuditEntry{
		Seq:              s.st.seq,
		Time:             time.Now().UTC(),
		Op:               op,
		RequestID:        requestID,
		Detail:           detail,
		SecurityRevision: s.st.secRevision,
	})
}

// --- 校验与工具 ---

func validVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func validateDigest(d string) error {
	if !strings.HasPrefix(d, digestPrefix) {
		return newError(ErrKindDigest, "摘要 %q 非法，应以 %q 开头", d, digestPrefix)
	}
	hexPart := strings.TrimPrefix(d, digestPrefix)
	if len(hexPart) != 64 {
		return newError(ErrKindDigest, "摘要 %q 非法，sha256 应为 64 个十六进制字符", d)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return newError(ErrKindDigest, "摘要 %q 包含非十六进制字符", d)
	}
	return nil
}

func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		na, _ := strconv.Atoi(pa[i])
		nb, _ := strconv.Atoi(pb[i])
		if na != nb {
			return na - nb
		}
	}
	return 0
}

// sortVersionsDesc 按版本号降序排序（版本号均已通过校验）。
func sortVersionsDesc(ids []PackageID) {
	sort.Slice(ids, func(i, j int) bool {
		return compareVersions(ids[i].Version, ids[j].Version) > 0
	})
}

func formatPath(path []PackageID) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = p.String()
	}
	return strings.Join(parts, " -> ")
}

// canonicalPublish 将发布请求规范化（依赖排序）后用于幂等指纹，
// 使依赖顺序不同但内容相同的请求被视为同一请求。
type publishFingerprint struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Digest  string    `json:"digest"`
	Deps    []DepSpec `json:"deps"`
}

func canonicalPublish(req PublishRequest) publishFingerprint {
	deps := append([]DepSpec{}, req.Deps...)
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return publishFingerprint{Name: req.Name, Version: req.Version, Digest: req.Digest, Deps: deps}
}

func fingerprint(op string, payload any) string {
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(append([]byte(op+"|"), data...))
	return hex.EncodeToString(sum[:])
}
