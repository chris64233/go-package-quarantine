package packagequarantine

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// store 以 JSONL（每行一个 JSON 对象）持久化五类数据：
//   - graph.jsonl：版本节点与图关系（pkgVersion，发布顺序）；
//   - requests.jsonl：外部请求号幂等记录；
//   - audit.jsonl：隔离/解除/豁免授予/豁免撤销安全事件（审计历史）；
//   - waivers.jsonl：豁免快照（授予时写一行；撤销时再写同一豁免的更新行，
//     回放时同一豁免序号以最后一行为准）；
//   - waiver_usage.jsonl：解析采用豁免的留痕（每次采用追加一行）。
//
// 写入采用 append 落盘，行级原子长度使重启重建简单直接：
// 服务启动时顺序回放这些日志即可还原全部内存状态。
type store struct {
	dir string

	graphFile       *os.File
	requestsFile    *os.File
	auditFile       *os.File
	waiversFile     *os.File
	waiverUsageFile *os.File

	graphW       *bufio.Writer
	requestsW    *bufio.Writer
	auditW       *bufio.Writer
	waiversW     *bufio.Writer
	waiverUsageW *bufio.Writer
}

const (
	graphFile       = "graph.jsonl"
	requestsFile    = "requests.jsonl"
	auditFile       = "audit.jsonl"
	waiversFile     = "waivers.jsonl"
	waiverUsageFile = "waiver_usage.jsonl"
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
	if st.waiversFile, st.waiversW, err = open(waiversFile); err != nil {
		st.close()
		return nil, err
	}
	if st.waiverUsageFile, st.waiverUsageW, err = open(waiverUsageFile); err != nil {
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

func (st *store) appendWaiver(w *RiskWaiver) error {
	return appendJSON(st.waiversW, st.waiversFile, w)
}

func (st *store) appendWaiverUsage(rec *WaiverUsageRecord) error {
	return appendJSON(st.waiverUsageW, st.waiverUsageFile, rec)
}

func (st *store) close() error {
	var firstErr error
	for _, c := range []interface{ Close() error }{
		st.graphFile, st.requestsFile, st.auditFile, st.waiversFile, st.waiverUsageFile,
	} {
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
		switch ev.Kind {
		case OpQuarantine:
			if s.active[ev.Target.key()] == nil {
				s.active[ev.Target.key()] = map[string]*SecurityEvent{}
			}
			s.active[ev.Target.key()][ev.Reason] = ev
		case OpRelease:
			delete(s.active[ev.Target.key()], ev.Reason)
			if len(s.active[ev.Target.key()]) == 0 {
				delete(s.active, ev.Target.key())
			}
		}
		// grant_waiver / revoke_waiver 不改变 active；豁免状态由 waivers.jsonl 还原。
	}

	// 4) 豁免快照：同一豁免序号可能出现多行（授予行 + 撤销更新行），最后一行为准。
	if err := readJSONL(s.store.dir, waiversFile, func(line []byte) error {
		var w RiskWaiver
		if err := json.Unmarshal(line, &w); err != nil {
			return err
		}
		cp := w
		s.waivers[w.Seq] = &cp
		return nil
	}); err != nil {
		return err
	}

	// 5) 解析采用豁免的留痕（仅审计用途，不参与安全状态重建）。
	if err := readJSONL(s.store.dir, waiverUsageFile, func(line []byte) error {
		var rec WaiverUsageRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return err
		}
		s.waiverUsage = append(s.waiverUsage, rec)
		return nil
	}); err != nil {
		return err
	}
	return nil
}
