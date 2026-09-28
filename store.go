package packagequarantine

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// store 以 JSONL（每行一个 JSON 对象）持久化三类数据：
//   - graph.jsonl：版本节点与图关系（pkgVersion，发布顺序）；
//   - requests.jsonl：外部请求号幂等记录；
//   - audit.jsonl：隔离/按原因解除/豁免授予/豁免撤销安全事件（审计历史）。
//
// 写入采用 append 落盘，行级原子长度使重启重建简单直接：
// 服务启动时顺序回放三个日志即可还原全部内存状态。
type store struct {
	dir string

	graphFile    *os.File
	requestsFile *os.File
	auditFile    *os.File

	graphW    *bufio.Writer
	requestsW *bufio.Writer
	auditW    *bufio.Writer
}

const (
	graphFile    = "graph.jsonl"
	requestsFile = "requests.jsonl"
	auditFile    = "audit.jsonl"
)

func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, errf(KindInvalidParam, "cannot open storage dir %q: %v", dir, err)
	}
	st := &store{dir: dir}
	open := func(name string) (*os.File, *bufio.Writer, error) {
		f, err := os.OpenFile(filepath.Join(dir, name),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, err
		}
		return f, bufio.NewWriter(f), nil
	}
	var err error
	if st.graphFile, st.graphW, err = open(graphFile); err != nil {
		return nil, err
	}
	if st.requestsFile, st.requestsW, err = open(requestsFile); err != nil {
		st.close()
		return nil, err
	}
	if st.auditFile, st.auditW, err = open(auditFile); err != nil {
		st.close()
		return nil, err
	}
	return st, nil
}

// appendJSON 将一个对象以 JSONL 行写入并 fsync，保证确认成功的操作已持久化。
func appendJSON(w *bufio.Writer, f *os.File, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return f.Sync()
}

func (st *store) appendGraph(pv *pkgVersion) error {
	return appendJSON(st.graphW, st.graphFile, pv)
}

func (st *store) appendRequests(rec *requestRecord) error {
	return appendJSON(st.requestsW, st.requestsFile, rec)
}

func (st *store) appendAudit(ev *SecurityEvent) error {
	return appendJSON(st.auditW, st.auditFile, ev)
}

func (st *store) close() error {
	var firstErr error
	for _, c := range []interface{ Close() error }{st.graphFile, st.requestsFile, st.auditFile} {
		if c != nil {
			if err := c.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// readJSONL 逐行解码文件并为每个非空行调用 add；文件不存在视为空。
func readJSONL(dir, name string, add func(line []byte) error) error {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if err := add(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// load 回放持久化日志，重建内存状态。必须在持锁状态下调用（当前由 NewService
// 在发布服务前调用，无并发可能）。
func (s *Service) load() error {
	// 1) 图节点
	var pvs []*pkgVersion
	if err := readJSONL(s.store.dir, graphFile, func(line []byte) error {
		var pv pkgVersion
		if err := json.Unmarshal(line, &pv); err != nil {
			return err
		}
		pvs = append(pvs, &pv)
		return nil
	}); err != nil {
		return err
	}
	// 发布按顺序落盘：子版本总在引用它的父版本之前。
	for _, pv := range pvs {
		s.versions[pv.Version.key()] = pv
	}

	// 2) 幂等请求
	var recs []*requestRecord
	if err := readJSONL(s.store.dir, requestsFile, func(line []byte) error {
		var rec requestRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return err
		}
		recs = append(recs, &rec)
		return nil
	}); err != nil {
		return err
	}
	for _, rec := range recs {
		s.requests[rec.ReqID] = rec
	}

	// 3) 安全审计事件
	var events []*SecurityEvent
	if err := readJSONL(s.store.dir, auditFile, func(line []byte) error {
		var ev SecurityEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return err
		}
		events = append(events, &ev)
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })

	for _, ev := range events {
		s.events = append(s.events, ev)
		if ev.Seq > s.nextSeq {
			s.nextSeq = ev.Seq
		}
		if ev.Rev > s.securityRev {
			s.securityRev = ev.Rev
		}
		k := ev.Target.key()
		switch ev.Kind {
		case OpQuarantine:
			if s.active[k] == nil {
				s.active[k] = map[string]*SecurityEvent{}
			}
			s.active[k][ev.Reason] = ev
		case OpRelease, OpReleaseRisk:
			// release_risk 自带 RiskReason；旧式单风险 release 只能在恰有一条
			// 生效隔离时出现，回放时按现存的唯一原因定位。
			reason := ev.RiskReason
			if ev.Kind == OpRelease {
				if risks := s.active[k]; len(risks) == 1 {
					for r := range risks {
						reason = r
					}
				}
			}
			delete(s.active[k], reason)
			if len(s.active[k]) == 0 {
				delete(s.active, k)
			}
			delete(s.waivers, waiverKey(ev.Target, reason))
		case OpWaiverGrant:
			s.waivers[waiverKey(ev.Target, ev.RiskReason)] = waiverFromEvent(ev)
		case OpWaiverRevoke:
			delete(s.waivers, waiverKey(ev.Target, ev.RiskReason))
		}
	}
	return nil
}
