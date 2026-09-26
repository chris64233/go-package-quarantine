package packagequarantine

import (
	"encoding/json"
	"fmt"
	"os"
)

// diskState 持久化到磁盘的完整状态：图关系、隔离记录、幂等记录、审计历史与安全修订号。
type diskState struct {
	Packages         []*PackageVersion      `json:"packages"`
	Quarantines      []*QuarantineRecord    `json:"quarantines"`
	Requests         map[string]*idemRecord `json:"requests"`
	Audit            []AuditEntry           `json:"audit"`
	SecurityRevision uint64                 `json:"security_revision"`
	Seq              uint64                 `json:"seq"`
}

// saveLocked 将状态原子写入磁盘（先写临时文件再重命名）。调用方须持有写锁。
func (s *Service) saveLocked() error {
	if s.path == "" {
		return nil
	}
	ds := diskState{
		Requests:         s.st.requests,
		Audit:            s.st.audit,
		SecurityRevision: s.st.secRevision,
		Seq:              s.st.seq,
	}
	for _, pv := range s.st.packages {
		ds.Packages = append(ds.Packages, pv)
	}
	for _, q := range s.st.quarantines {
		ds.Quarantines = append(ds.Quarantines, q)
	}
	data, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化状态失败: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("写入状态文件失败: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("替换状态文件失败: %w", err)
	}
	return nil
}

// load 从磁盘恢复状态并重建索引；文件不存在时从空状态开始。
func (s *Service) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取状态文件失败: %w", err)
	}
	var ds diskState
	if err := json.Unmarshal(data, &ds); err != nil {
		return fmt.Errorf("解析状态文件失败: %w", err)
	}

	st := newState()
	st.secRevision = ds.SecurityRevision
	st.seq = ds.Seq
	st.audit = ds.Audit
	if ds.Requests != nil {
		st.requests = ds.Requests
	}
	for _, pv := range ds.Packages {
		st.packages[pv.ID] = pv
		if st.byNameVer[pv.ID.Name] == nil {
			st.byNameVer[pv.ID.Name] = map[string]PackageID{}
		}
		st.byNameVer[pv.ID.Name][pv.ID.Version] = pv.ID
		st.byName[pv.ID.Name] = append(st.byName[pv.ID.Name], pv.ID)
	}
	for _, ids := range st.byName {
		sortVersionsDesc(ids)
	}
	for _, q := range ds.Quarantines {
		st.quarantines[q.ID] = q
	}
	s.st = st
	return nil
}
