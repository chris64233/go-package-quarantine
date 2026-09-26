package packagequarantine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
	if _, err := s.Release("r-util", v("util", "1"), "fixed"); err != nil {
		t.Fatal(err)
	}
	// 再隔离另一个版本，验证 active 集合回放正确。
	if _, err := s.Quarantine("q-lib", v("lib", "1"), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// 三个 JSONL 文件均应存在且非空。
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
	r2, err := s2.Release("r-util", v("util", "1"), "fixed")
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
