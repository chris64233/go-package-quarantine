package packagequarantine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistGraphRequestsAndAudit(t *testing.T) {
	dir := t.TempDir()

	s, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustPublish(t, s, "p-util", "util", "1")
	mustPublish(t, s, "p-lib", "lib", "1", dep("util", "1"))
	mustPublish(t, s, "p-app", "app", "1", dep("lib", "1"))
	q, err := s.Quarantine("q-util", v("util", "1"), "CVE-x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Release("r-util", v("util", "1"), "CVE-x"); err != nil {
		t.Fatal(err)
	}
	// 再隔离另一个版本，验证 active 集合回放正确。
	if _, err := s.Quarantine("q-lib", v("lib", "1"), "lib-risk"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// 原始三个 JSONL 文件均应存在且非空；新增的两个豁免文件由存储打开时创建
	// （本用例没有豁免，故允许为空）。
	for _, name := range []string{graphFile, requestsFile, auditFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() == 0 {
			t.Fatalf("persisted file %s missing/empty: %v", name, err)
		}
	}

	// 重开：图、修订号、审计、生效隔离全部还原。
	s2, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if s2.SecurityRev() != 3 {
		t.Fatalf("restored rev = %d, want 3", s2.SecurityRev())
	}
	ver, deps, ok := s2.Snapshot().GetVersion("app", "1")
	if !ok || ver.Digest != digest("app@1") || len(deps) != 1 || deps[0].Digest == "" {
		t.Fatalf("restored graph wrong: %+v deps=%+v ok=%v", ver, deps, ok)
	}

	events := s2.Snapshot().AuditEvents()
	if len(events) != 3 {
		t.Fatalf("restored audit len = %d", len(events))
	}
	if events[0].Seq != 1 || events[2].Seq != 3 || events[1].RelatedSeq != q.Event.Seq {
		t.Fatalf("restored events wrong: %+v", events)
	}

	// lib 当前被隔离：app 经 lib 仍被阻塞；util 已解除，自身可解析。
	var blocked *BlockedError
	if _, err := s2.Resolve("app", "1"); !errors.As(err, &blocked) {
		t.Fatalf("app should remain blocked after restore: %v", err)
	}
	if got := pathKeys(blocked.Path); got[len(got)-1] != "lib@1" {
		t.Fatalf("path = %v, want ending lib@1", got)
	}
	if _, err := s2.Resolve("util", "1"); err != nil {
		t.Fatalf("util must be installable after restore: %v", err)
	}

	// 幂等记录也被回放：同号异内容冲突；同号同内容重放且不增加修订号。
	_, err = s2.Quarantine("q-util", v("util", "1"), "different reason")
	assertKind(t, err, KindIdempotent)
	r2, err := s2.Release("r-util", v("util", "1"), "CVE-x")
	if err != nil || !r2.Replayed {
		t.Fatalf("idempotent replay after restore: %+v %v", r2, err)
	}
	if s2.SecurityRev() != 3 {
		t.Fatalf("rev = %d, replay must not advance rev", s2.SecurityRev())
	}
}

func TestRestartOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// 目录已创建但尚无任何日志文件：重开不应报错。
	s2, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.SecurityRev() != 0 {
		t.Fatalf("rev = %d", s2.SecurityRev())
	}
}

func TestMemoryModeWorks(t *testing.T) {
	s, err := NewService("")
	if err != nil {
		t.Fatal(err)
	}
	mustPublish(t, s, "p", "lib", "1")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistWaiversAndUsageAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustPublish(t, s, "p-util", "util", "1")
	mustPublish(t, s, "p-lib", "lib", "1", dep("util", "1"))
	mustPublish(t, s, "p-app", "app", "1", dep("lib", "1"))

	if _, err := s.Quarantine("q-u", v("util", "1"), "CVE-U"); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(2 * time.Hour)
	g, err := s.GrantWaiver("w-u", v("util", "1"), "CVE-U", exp, Approval{Approver: "alice", Ticket: "SEC-9"})
	if err != nil {
		t.Fatal(err)
	}
	// 一次成功采用豁免的解析，产生一条 usage 留痕。
	if r, err := s.Resolve("app", "1"); err != nil {
		t.Fatalf("resolve with waiver: %v", err)
	} else if len(r.Waivers) != 1 {
		t.Fatalf("waiver uses = %+v", r.Waivers)
	}
	// 撤销该条豁免后，app 立即重新被 CVE-U 阻断。
	if _, err := s.RevokeWaiver("rv-u", v("util", "1"), "CVE-U", "withdrawn"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{waiversFile, waiverUsageFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() == 0 {
			t.Fatalf("persisted file %s missing/empty: %v", name, err)
		}
	}

	s2, err := NewService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	// 审计事件：隔离、授予、撤销 => 3 条，rev 推进到 3。
	events := s2.Snapshot().AuditEvents()
	if len(events) != 3 {
		t.Fatalf("audit events = %d, want 3", len(events))
	}
	if got := s2.SecurityRev(); got != 3 {
		t.Fatalf("restored rev = %d, want 3", got)
	}

	// 还原的豁免已撤销，故不出现于有效豁免集合，app 仍被 CVE-U 阻塞。
	if ws := s2.Snapshot().ActiveWaivers(); len(ws) != 0 {
		t.Fatalf("revoked waiver must not restore active: %+v", ws)
	}
	var blocked *BlockedError
	if _, err := s2.Resolve("app", "1"); !errors.As(err, &blocked) {
		t.Fatalf("app must be blocked after restore: %v", err)
	}
	if blocked.Reason != "CVE-U" {
		t.Fatalf("block reason = %q", blocked.Reason)
	}

	// 已撤销豁免的状态字段也被还原。
	w := s2.waivers[g.Waiver.Seq]
	if w == nil || w.RevokedAt.IsZero() || w.RevokedReqID != "rv-u" ||
		w.QuarantineSeq != 1 || w.Approval.Ticket != "SEC-9" {
		t.Fatalf("restored waiver = %+v", w)
	}

	// 采用留痕被还原（不随撤销而删除——它记录“当时为什么允许”）。
	usage := s2.WaiverUsage()
	if len(usage) != 1 || usage[0].Root != v("app", "1") || len(usage[0].Uses) != 1 ||
		usage[0].Uses[0].WaiverSeq != g.Waiver.Seq || usage[0].Uses[0].Reason != "CVE-U" {
		t.Fatalf("restored usage = %+v", usage)
	}

	// 授予/撤销的幂等记录被回放：同号同内容重放不推进修订号。
	rg, err := s2.GrantWaiver("w-u", v("util", "1"), "CVE-U", exp,
		Approval{Approver: "alice", Ticket: "SEC-9"})
	if err != nil || !rg.Replayed {
		t.Fatalf("grant replay after restore: %+v %v", rg, err)
	}
	rv, err := s2.RevokeWaiver("rv-u", v("util", "1"), "CVE-U", "withdrawn")
	if err != nil || !rv.Replayed {
		t.Fatalf("revoke replay after restore: %+v %v", rv, err)
	}
	if got := s2.SecurityRev(); got != 3 {
		t.Fatalf("rev = %d after replay, must stay 3", got)
	}
}
