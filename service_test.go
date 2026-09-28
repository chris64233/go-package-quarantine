package packagequarantine

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// digest 生成合法格式的测试摘要，相同输入永远得到相同摘要。
func digest(seed string) string {
	const hex = "0123456789abcdef"
	h := make([]byte, 64)
	var acc uint32 = 0xcbf29ce4
	for i := 0; i < len(seed); i++ {
		acc = acc*0x01000193 ^ uint32(seed[i])
	}
	for i := range h {
		acc = acc*1103515245 + 12345
		h[i] = hex[(acc>>16)%16]
	}
	return "sha256:" + string(h)
}

func v(name, version string) Version {
	return Version{Name: name, Version: version, Digest: digest(name + "@" + version)}
}

func dep(name, version string) Dependency {
	return Dependency{Name: name, Version: version}
}

func mustPublish(t *testing.T, s *Service, reqID, name, version string, deps ...Dependency) *PublishResult {
	t.Helper()
	res, err := s.Publish(PublishRequest{
		RequestID: reqID,
		Name:      name,
		Version:   version,
		Digest:    digest(name + "@" + version),
		Deps:      deps,
	})
	if err != nil {
		t.Fatalf("Publish(%s@%s) unexpected error: %v", name, version, err)
	}
	return res
}

func assertKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	pe := ErrorAs(err)
	if pe == nil {
		t.Fatalf("want *Error kind %s, got %v", want, err)
	}
	if pe.Kind != want {
		t.Fatalf("want error kind %s, got %s (%v)", want, pe.Kind, err)
	}
}

func TestPublishResolvesDirectDependencies(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "r1", "util", "1.0.0")
	mustPublish(t, s, "r2", "lib", "1.0.0", dep("util", "1.0.0"))
	res := mustPublish(t, s, "r3", "app", "1.0.0", dep("lib", "1.0.0"))

	if len(res.Deps) != 1 || res.Deps[0] != v("lib", "1.0.0") {
		t.Fatalf("resolved deps = %+v, want [lib@1.0.0 with digest]", res.Deps)
	}

	snap := s.Snapshot()
	got, deps, ok := snap.GetVersion("app", "1.0.0")
	if !ok {
		t.Fatal("app@1.0.0 not found")
	}
	if got.Digest == "" || deps[0].Digest == "" {
		t.Fatalf("stored references must carry digests: %+v %+v", got, deps)
	}
}

func TestPublishFailsOnMissingDependency(t *testing.T) {
	s, _ := NewService("")
	_, err := s.Publish(PublishRequest{
		RequestID: "r1", Name: "app", Version: "1.0.0",
		Digest: digest("app@1.0.0"),
		Deps:   []Dependency{dep("ghost", "9.9.9")},
	})
	assertKind(t, err, KindDependency)
	if !strings.Contains(err.Error(), "ghost@9.9.9") {
		t.Fatalf("error should name the missing dependency, got %v", err)
	}

	// 失败后不能留下版本或占用请求号。
	if _, _, ok := s.Snapshot().GetVersion("app", "1.0.0"); ok {
		t.Fatal("failed publish must not create the version")
	}
	if _, err := s.Publish(PublishRequest{
		RequestID: "r1", Name: "other", Version: "1.0.0",
		Digest: digest("other@1.0.0"),
	}); err != nil {
		t.Fatalf("request id from failed publish should be reusable, got %v", err)
	}
}

func TestPublishRejectsSelfCycle(t *testing.T) {
	// 版本不可变、依赖只指向已发布版本：新节点入图前不存在于图中，
	// 顺序发布不可能构造出“经多个节点回到新节点”的环；唯一可被声明的环是自依赖。
	s, _ := NewService("")
	_, err := s.Publish(PublishRequest{
		RequestID: "self", Name: "lonely", Version: "1.0.0",
		Digest: digest("lonely@1.0.0"),
		Deps:   []Dependency{dep("lonely", "1.0.0")},
	})
	assertKind(t, err, KindDependency)
	if !strings.Contains(err.Error(), "cannot depend on itself") {
		t.Fatalf("want self-dependency error, got %v", err)
	}
	if _, _, ok := s.Snapshot().GetVersion("lonely", "1.0.0"); ok {
		t.Fatal("rejected version must not be stored")
	}
}

func TestFindPathToDetectsBackEdge(t *testing.T) {
	// 环检测辅助函数的直接单测：即使图中因外部数据迁移已存在环，
	// 也必须能找出回到目标键的路径（防御性检查，发布时拦截）。
	s, _ := NewService("")
	a := v("a", "1")
	b := v("b", "1")
	s.versions[a.key()] = &pkgVersion{Version: a, Deps: []Version{b}}
	s.versions[b.key()] = &pkgVersion{Version: b, Deps: []Version{a}}

	if path := findPathTo(s.versions, []Version{b}, a.key()); len(path) != 2 ||
		path[0] != b.key() || path[1] != a.key() {
		t.Fatalf("want [b@1 a@1], got %v", path)
	}
	if path := findPathTo(s.versions, []Version{a}, a.key()); len(path) == 0 {
		t.Fatal("expected to find path back to a")
	}
}

func TestPublishInvalidParams(t *testing.T) {
	s, _ := NewService("")
	cases := []struct {
		name string
		req  PublishRequest
	}{
		{"missing request id", PublishRequest{Name: "a", Version: "1", Digest: digest("a@1")}},
		{"missing name", PublishRequest{RequestID: "r", Version: "1", Digest: digest("a@1")}},
		{"missing version", PublishRequest{RequestID: "r", Name: "a", Digest: digest("a@1")}},
		{"bad digest", PublishRequest{RequestID: "r", Name: "a", Version: "1", Digest: "deadbeef"}},
		{"blank dependency", PublishRequest{RequestID: "r", Name: "a", Version: "1", Digest: digest("a@1"),
			Deps: []Dependency{{Name: "", Version: "1"}}}},
		{"duplicate dependency", PublishRequest{RequestID: "r", Name: "app", Version: "1",
			Digest: digest("app@1"),
			Deps:   []Dependency{dep("u", "1"), dep("u", "1")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustPublish(t, s, "u-exists", "u", "1")
			_, err := s.Publish(tc.req)
			assertKind(t, err, KindInvalidParam)
		})
	}
}

func TestPublishDuplicateDependencyRefersExisting(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "u", "u", "1")
	_, err := s.Publish(PublishRequest{
		RequestID: "r", Name: "app", Version: "1",
		Digest: digest("app@1"),
		Deps:   []Dependency{dep("u", "1"), dep("u", "1")},
	})
	assertKind(t, err, KindInvalidParam)
}

func TestDigestImmutability(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "r1", "lib", "1.0.0")

	// 同名同版本、不同摘要 -> 摘要冲突。
	_, err := s.Publish(PublishRequest{
		RequestID: "r2", Name: "lib", Version: "1.0.0", Digest: digest("different"),
	})
	assertKind(t, err, KindDigest)

	// 相同身份（含相同摘要）但不带/带不同请求号：返回已发布版本，不可变对象天然幂等。
	res, err := s.Publish(PublishRequest{
		RequestID: "r3", Name: "lib", Version: "1.0.0", Digest: digest("lib@1.0.0"),
	})
	if err != nil {
		t.Fatalf("republish same identity should succeed idempotently: %v", err)
	}
	if res.Version != v("lib", "1.0.0") {
		t.Fatalf("got %+v", res.Version)
	}
}

func TestIdempotencyReplayAndConflict(t *testing.T) {
	s, _ := NewService("")
	req := PublishRequest{
		RequestID: "req-1", Name: "lib", Version: "1.0.0", Digest: digest("lib@1.0.0"),
	}
	first, err := s.Publish(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Publish(req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || first.Version != second.Version {
		t.Fatalf("same request should replay: first=%+v second=%+v", first, second)
	}

	// 同号异内容 -> 冲突。
	req.Digest = digest("tampered")
	_, err = s.Publish(req)
	assertKind(t, err, KindIdempotent)

	// 同一请求号不能跨操作复用。
	if _, err := s.Quarantine("req-1", v("lib", "1.0.0"), "risk"); err == nil {
		t.Fatal("reusing publish request id for quarantine must conflict")
	} else {
		assertKind(t, err, KindIdempotent)
	}
}

func buildChain(t *testing.T, s *Service) {
	t.Helper()
	mustPublish(t, s, "p-util", "util", "1.0.0")
	mustPublish(t, s, "p-lib", "lib", "1.0.0", dep("util", "1.0.0"))
	mustPublish(t, s, "p-app", "app", "1.0.0", dep("lib", "1.0.0"))
}

func keys(vs []Version) []string {
	out := make([]string, len(vs))
	for i, x := range vs {
		out[i] = x.key()
	}
	return out
}

func TestResolveClosure(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s)
	// 额外的菱形依赖用于验证去重：app -> lib, tool；lib -> util；tool -> util。
	mustPublish(t, s, "p-tool", "tool", "1.0.0", dep("util", "1.0.0"))
	mustPublish(t, s, "p-app2", "app", "2.0.0", dep("lib", "1.0.0"), dep("tool", "1.0.0"))

	res, err := s.Resolve("app", "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"app@2.0.0": true, "lib@1.0.0": true, "tool@1.0.0": true, "util@1.0.0": true,
	}
	got := map[string]bool{}
	for _, x := range res.Versions {
		got[x.key()] = true
	}
	if len(res.Versions) != 4 || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("closure = %v, want %v", keys(res.Versions), want)
	}
	// 排序稳定
	for i := 1; i < len(res.Versions); i++ {
		if res.Versions[i-1].key() >= res.Versions[i].key() {
			t.Fatalf("versions not sorted/deduped: %v", keys(res.Versions))
		}
	}
}

func TestQuarantinePropagatesWithExplainablePath(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s)

	before := s.Snapshot()
	if before.Rev() != 0 {
		t.Fatalf("initial rev = %d, want 0", before.Rev())
	}

	res, err := s.Quarantine("q-util", v("util", "1.0.0"), "CVE-2026-0001")
	if err != nil {
		t.Fatal(err)
	}
	if res.Event.Rev != 1 || res.Replayed {
		t.Fatalf("event = %+v", res.Event)
	}

	// 旧快照的全程解析不受隔离影响。
	if r, err := before.Resolve("app", "1.0.0"); err != nil {
		t.Fatalf("stale snapshot must stay readable: %v", err)
	} else if len(r.Versions) != 3 {
		t.Fatalf("stale closure = %v", r.Versions)
	}

	// 直接被隔离版本。
	_, err = s.Resolve("util", "1.0.0")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("want BlockedError, got %v", err)
	}
	if got := pathKeys(blocked.Path); fmt.Sprint(got) != "[util@1.0.0]" {
		t.Fatalf("direct quarantine path = %v", got)
	}

	// 传递依赖方：app -> lib -> util，必须返回可解释路径。
	_, err = s.Resolve("app", "1.0.0")
	if !errors.As(err, &blocked) {
		t.Fatalf("want BlockedError, got %v", err)
	}
	if got := pathKeys(blocked.Path); fmt.Sprint(got) != "[app@1.0.0 lib@1.0.0 util@1.0.0]" {
		t.Fatalf("propagation path = %v", got)
	}
	if blocked.Quarantined != v("util", "1.0.0") {
		t.Fatalf("quarantined target = %+v", blocked.Quarantined)
	}
	if blocked.Rev != 1 {
		t.Fatalf("blocked rev = %d", blocked.Rev)
	}

	// 无关版本照常解析。
	mustPublish(t, s, "p-other", "other", "1.0.0")
	if r, err := s.Resolve("other", "1.0.0"); err != nil || len(r.Versions) != 1 {
		t.Fatalf("unrelated resolution = %+v, %v", r, err)
	}
}

func pathKeys(path []Version) []string {
	out := make([]string, len(path))
	for i, x := range path {
		out[i] = x.key()
	}
	return out
}

func TestReleaseDoesNotRestoreVersionsBlockedByOtherPaths(t *testing.T) {
	s, _ := NewService("")
	// B 是漏洞库；X、Y 都依赖 B；A 同时依赖 X、Y。
	mustPublish(t, s, "b", "b", "1")
	mustPublish(t, s, "x", "x", "1", dep("b", "1"))
	mustPublish(t, s, "y", "y", "1", dep("b", "1"))
	mustPublish(t, s, "a", "a", "1", dep("x", "1"), dep("y", "1"))

	// 直接隔离 B：A、X、Y 全部受影响。
	if _, err := s.Quarantine("q-b", v("b", "1"), "risk-b"); err != nil {
		t.Fatal(err)
	}
	// 另外因不同原因隔离 X。
	if _, err := s.Quarantine("q-x", v("x", "1"), "risk-x"); err != nil {
		t.Fatal(err)
	}
	if s.SecurityRev() != 2 {
		t.Fatalf("rev = %d, want 2", s.SecurityRev())
	}

	// 解除 B 上 risk-b 这一条隔离；但 A 仍经 X 被阻塞，X 自身也仍被隔离。
	if _, err := s.Release("r-b", v("b", "1"), "risk-b"); err != nil {
		t.Fatal(err)
	}
	if s.SecurityRev() != 3 {
		t.Fatalf("rev = %d, want 3", s.SecurityRev())
	}
	if _, err := s.Resolve("b", "1"); err != nil {
		t.Fatalf("B itself must be installable again: %v", err)
	}
	if _, err := s.Resolve("y", "1"); err != nil {
		t.Fatalf("Y must be restored when B is released: %v", err)
	}
	var blocked *BlockedError
	_, err := s.Resolve("a", "1")
	if !errors.As(err, &blocked) {
		t.Fatalf("A must still be blocked via X, got %v", err)
	}
	if got := pathKeys(blocked.Path); got[len(got)-1] != "x@1" || got[0] != "a@1" {
		t.Fatalf("block path should end at x@1, got %v", got)
	}

	// 再解除 X，全部恢复。
	if _, err := s.Release("r-x", v("x", "1"), "risk-x"); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Resolve("a", "1"); err != nil || len(r.Versions) != 4 {
		t.Fatalf("A closure after all releases: %+v err=%v", r, err)
	}
}

func TestQuarantineValidationAndStateConflicts(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p", "lib", "1")

	// 目标不存在。
	if _, err := s.Quarantine("q1", v("ghost", "1"), "risk"); err == nil {
		t.Fatal("quarantine of missing version must fail")
	} else {
		assertKind(t, err, KindNotFound)
	}

	// 摘要不匹配。
	wrong := Version{Name: "lib", Version: "1", Digest: digest("nope")}
	_, err := s.Quarantine("q2", wrong, "risk")
	assertKind(t, err, KindDigest)

	// 参数缺失。
	_, err = s.Quarantine("", v("lib", "1"), "risk")
	assertKind(t, err, KindInvalidParam)
	_, err = s.Quarantine("q-no-reason", v("lib", "1"), "  ")
	assertKind(t, err, KindInvalidParam)

	// 同原因重复隔离冲突。
	if _, err := s.Quarantine("q3", v("lib", "1"), "dup-risk"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Quarantine("q4", v("lib", "1"), "dup-risk")
	assertKind(t, err, KindConflict)

	// 不同原因的再次隔离允许（风险叠加）。
	if _, err := s.Quarantine("q5", v("lib", "1"), "other-risk"); err != nil {
		t.Fatalf("quarantine for a different reason must succeed: %v", err)
	}

	// 解除不存在的原因 -> 冲突；解除未发布版本 -> not_found。
	_, err = s.Release("r0", v("lib", "1"), "never-existed")
	assertKind(t, err, KindConflict)
	_, err = s.Release("r1", v("ghost", "1"), "risk")
	assertKind(t, err, KindNotFound)
}

func TestSecurityIdempotencyReplayDoesNotBumpRev(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p", "lib", "1")

	first, err := s.Quarantine("q-1", v("lib", "1"), "reason A")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Quarantine("q-1", v("lib", "1"), "reason A")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.Event.Seq != first.Event.Seq {
		t.Fatalf("replay must return same event: %+v vs %+v", first.Event, second.Event)
	}
	if s.SecurityRev() != 1 {
		t.Fatalf("rev = %d, replay must not bump rev", s.SecurityRev())
	}

	// 同号但原因不同 -> 冲突。
	_, err = s.Quarantine("q-1", v("lib", "1"), "reason B")
	assertKind(t, err, KindIdempotent)

	rel, err := s.Release("r-1", v("lib", "1"), "reason A")
	if err != nil {
		t.Fatal(err)
	}
	rel2, err := s.Release("r-1", v("lib", "1"), "reason A")
	if err != nil || !rel2.Replayed || rel2.Event.Seq != rel.Event.Seq {
		t.Fatalf("release replay mismatch: %+v err=%v", rel2, err)
	}
	if s.SecurityRev() != 2 {
		t.Fatalf("rev = %d, want 2", s.SecurityRev())
	}
	// 解除重放后再次解除同一原因 -> 冲突（该原因已无生效隔离）。
	_, err = s.Release("r-other", v("lib", "1"), "reason A")
	assertKind(t, err, KindConflict)
}

func TestImpactQuery(t *testing.T) {
	s, _ := NewService("")
	// util <- lib <- app；tool 也依赖 util；isolated 独立。
	mustPublish(t, s, "u", "util", "1")
	mustPublish(t, s, "l", "lib", "1", dep("util", "1"))
	mustPublish(t, s, "a", "app", "1", dep("lib", "1"))
	mustPublish(t, s, "t", "tool", "1", dep("util", "1"))
	mustPublish(t, s, "i", "isolated", "1")

	rep, err := s.Impact("util", "1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.DirectlyQuarantined {
		t.Fatal("util should not be quarantined yet")
	}
	got := map[string]ImpactEntry{}
	for _, e := range rep.Affected {
		got[e.Version.key()] = e
	}
	if len(got) != 3 {
		t.Fatalf("affected = %d entries: %+v", len(got), rep.Affected)
	}
	if p := pathKeys(got["app@1"].Path); fmt.Sprint(p) != "[app@1 lib@1 util@1]" {
		t.Fatalf("app path = %v", p)
	}
	if p := pathKeys(got["tool@1"].Path); fmt.Sprint(p) != "[tool@1 util@1]" {
		t.Fatalf("tool path = %v", p)
	}
	for _, e := range got {
		if e.Blocked {
			t.Fatalf("%s should not be blocked before quarantine", e.Version.key())
		}
	}

	if _, err := s.Quarantine("q", v("util", "1"), "risk"); err != nil {
		t.Fatal(err)
	}
	rep, err = s.Impact("util", "1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DirectlyQuarantined || rep.QuarantineEventSeq == 0 {
		t.Fatalf("quarantine flags = %+v", rep)
	}
	for _, e := range rep.Affected {
		if !e.Blocked {
			t.Fatalf("%s must be reported blocked after quarantine", e.Version.key())
		}
	}
	if rep.Rev != 1 {
		t.Fatalf("impact rev = %d", rep.Rev)
	}

	if _, err := s.Impact("ghost", "1"); err == nil {
		t.Fatal("impact on missing version must fail")
	} else {
		assertKind(t, err, KindNotFound)
	}
}

func TestAuditHistory(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p", "lib", "1")
	q, _ := s.Quarantine("q", v("lib", "1"), "incident-1")
	r, _ := s.Release("r", v("lib", "1"), "incident-1")

	events := s.Snapshot().AuditEvents()
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	if events[0].Kind != OpQuarantine || events[1].Kind != OpRelease {
		t.Fatalf("event kinds = %s, %s", events[0].Kind, events[1].Kind)
	}
	if events[0].Seq != 1 || events[1].Seq != 2 || events[1].RelatedSeq != q.Event.Seq {
		t.Fatalf("event seq/link = %+v %+v", events[0], events[1])
	}
	if r.Event.Rev != 2 || events[1].Rev != 2 {
		t.Fatal("rev should advance on both operations")
	}
	// 调用方修改返回切片不得影响服务内部状态。
	events[0].Reason = "tampered"
	if s.Snapshot().AuditEvents()[0].Reason != "incident-1" {
		t.Fatal("audit history must be defensively copied")
	}
}

func TestSnapshotPinsOneSecurityRevision(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s)

	snap := s.Snapshot()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 持快照期间进行多次安全操作。
		_, _ = s.Quarantine("q1", v("util", "1.0.0"), "risk-1")
		_, _ = s.Release("r1", v("util", "1.0.0"), "risk-1")
		_, _ = s.Quarantine("q2", v("util", "1.0.0"), "risk-2")
	}()
	<-done

	if snap.Rev() != 0 {
		t.Fatalf("snapshot rev changed: %d", snap.Rev())
	}
	r, err := snap.Resolve("app", "1.0.0")
	if err != nil {
		t.Fatalf("pinned snapshot must resolve against rev 0: %v", err)
	}
	if r.Rev != 0 || len(r.Versions) != 3 {
		t.Fatalf("pinned resolution = %+v", r)
	}
	if s.Snapshot().Rev() != 3 {
		t.Fatalf("current rev = %d, want 3", s.Snapshot().Rev())
	}
}

func TestLatePublishCannotBypassConfirmedQuarantine(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p-lib", "lib", "1")
	// 隔离先被确认。
	if _, err := s.Quarantine("q-lib", v("lib", "1"), "confirmed incident"); err != nil {
		t.Fatal(err)
	}
	// 迟到的发布：新版本沿新边依赖到已隔离的 lib。
	mustPublish(t, s, "p-app-late", "app", "1", dep("lib", "1"))
	_, err := s.Resolve("app", "1")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("late publish must not bypass quarantine, got %v", err)
	}
	if got := pathKeys(blocked.Path); fmt.Sprint(got) != "[app@1 lib@1]" {
		t.Fatalf("path = %v", got)
	}
}

func TestConcurrentLatePublishResolveAfterConfirmedQuarantine(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p-vuln", "vuln", "1")

	// 隔离先确认（屏障），此后任何迟到发布都不得绕开它。
	if _, err := s.Quarantine("q-vuln", v("vuln", "1"), "confirmed"); err != nil {
		t.Fatal(err)
	}

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})

	// 并发迟到发布：每个新包都（传递）依赖 vuln。
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			_, _ = s.Publish(PublishRequest{
				RequestID: fmt.Sprintf("pub-%d", i),
				Name:      fmt.Sprintf("dep%d", i), Version: "1",
				Digest: digest(fmt.Sprintf("dep%d@1", i)),
				Deps:   []Dependency{dep("vuln", "1")},
			})
		}()
	}
	// 并发解析：等到各自的发布落地后解析，必须全部被阻塞。
	blockedFlags := make([]bool, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("dep%d", i)
			for {
				if _, _, ok := s.Snapshot().GetVersion(name, "1"); ok {
					break
				}
			}
			_, err := s.Resolve(name, "1")
			var blocked *BlockedError
			blockedFlags[i] = errors.As(err, &blocked)
		}()
	}
	close(start)
	wg.Wait()

	for i, blocked := range blockedFlags {
		if !blocked {
			t.Fatalf("dep%d resolution bypassed the confirmed quarantine", i)
		}
	}
	if s.SecurityRev() != 1 {
		t.Fatalf("rev = %d, want 1", s.SecurityRev())
	}
}

func TestConcurrentQuarantineSameRequestAppliesOnce(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p", "lib", "1")

	const n = 40
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	var applied, replayed int
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			res, err := s.Quarantine("q-only", v("lib", "1"), "same")
			if err != nil {
				t.Errorf("quarantine error: %v", err)
				return
			}
			mu.Lock()
			if res.Replayed {
				replayed++
			} else {
				applied++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if applied != 1 || applied+replayed != n {
		t.Fatalf("applied=%d replayed=%d (total=%d)", applied, replayed, n)
	}
	if s.SecurityRev() != 1 {
		t.Fatalf("rev = %d, identical concurrent requests must apply once", s.SecurityRev())
	}
}

func TestConcurrentIdempotencyConflict(t *testing.T) {
	s, _ := NewService("")
	const n = 30
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	var sameOK, conflicts int
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			d := digest("lib@1")
			if i%2 == 1 {
				d = digest("different") // 同号异内容，必须冲突
			}
			_, err := s.Publish(PublishRequest{
				RequestID: "same-req", Name: "lib", Version: "1", Digest: d,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				sameOK++ // 同内容请求：首次写入或按不可变身份幂等返回
			case ErrorAs(err).Kind == KindIdempotent:
				conflicts++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if sameOK != n/2 {
		t.Fatalf("same-content successes = %d, want %d", sameOK, n/2)
	}
	if conflicts != n/2 {
		t.Fatalf("conflicts = %d, want %d", conflicts, n/2)
	}
	// 最终摘要必然是两个候选之一，冲突内容绝不会与获胜内容以外的值混杂。
	got, _, _ := s.Snapshot().GetVersion("lib", "1")
	if got.Digest != digest("lib@1") && got.Digest != digest("different") {
		t.Fatalf("stored digest = %s is neither candidate", got.Digest)
	}
}

func TestResolveNotFound(t *testing.T) {
	s, _ := NewService("")
	if _, err := s.Resolve("nope", "1"); err == nil {
		t.Fatal("resolve missing version must fail")
	} else {
		assertKind(t, err, KindNotFound)
	}
}
