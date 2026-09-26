package packagequarantine

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// digestOf 生成测试用的合法摘要。
func digestOf(seed string) string {
	return "sha256:" + strings.Repeat(seed, 64)[:64]
}

func mustPublish(t *testing.T, s *Service, reqID, name, version, digestSeed string, deps ...DepSpec) *PackageVersion {
	t.Helper()
	pv, err := s.Publish(PublishRequest{
		RequestID: reqID,
		Name:      name,
		Version:   version,
		Digest:    digestOf(digestSeed),
		Deps:      deps,
	})
	if err != nil {
		t.Fatalf("发布 %s@%s 失败: %v", name, version, err)
	}
	return pv
}

func dep(name, version string) DepSpec { return DepSpec{Name: name, Version: version} }

func mustKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望 %s 错误，实际无错误", want)
	}
	got, ok := KindOf(err)
	if !ok || got != want {
		t.Fatalf("期望错误类别 %s，实际 %v", want, err)
	}
}

func TestPublishStoresResolvedDeps(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "r1", "lib", "1.0.0", "a")
	pv := mustPublish(t, s, "r2", "app", "1.0.0", "b", dep("lib", "1.0.0"))

	want := PackageID{Name: "lib", Version: "1.0.0", Digest: digestOf("a")}
	if len(pv.Deps) != 1 || pv.Deps[0] != want {
		t.Fatalf("解析后的直接依赖不正确: %+v", pv.Deps)
	}
	if pv.ID != (PackageID{Name: "app", Version: "1.0.0", Digest: digestOf("b")}) {
		t.Fatalf("版本坐标不正确: %+v", pv.ID)
	}
}

func TestPublishParamAndDigestErrors(t *testing.T) {
	s, _ := NewService("")
	cases := []struct {
		name string
		req  PublishRequest
		want ErrorKind
	}{
		{"缺少请求号", PublishRequest{Name: "a", Version: "1.0.0", Digest: digestOf("a")}, ErrKindParam},
		{"缺少名称", PublishRequest{RequestID: "r1", Version: "1.0.0", Digest: digestOf("a")}, ErrKindParam},
		{"版本号非法", PublishRequest{RequestID: "r1", Name: "a", Version: "1.0", Digest: digestOf("a")}, ErrKindParam},
		{"摘要缺前缀", PublishRequest{RequestID: "r1", Name: "a", Version: "1.0.0", Digest: "abcd"}, ErrKindDigest},
		{"摘要长度不对", PublishRequest{RequestID: "r1", Name: "a", Version: "1.0.0", Digest: "sha256:abcd"}, ErrKindDigest},
		{"摘要含非法字符", PublishRequest{RequestID: "r1", Name: "a", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("zz", 32)}, ErrKindDigest},
		{"依赖名称为空", PublishRequest{RequestID: "r1", Name: "a", Version: "1.0.0", Digest: digestOf("a"), Deps: []DepSpec{{Version: "1.0.0"}}}, ErrKindParam},
		{"依赖版本非法", PublishRequest{RequestID: "r1", Name: "a", Version: "1.0.0", Digest: digestOf("a"), Deps: []DepSpec{{Name: "b", Version: "x"}}}, ErrKindParam},
		{"依赖重复", PublishRequest{RequestID: "r1", Name: "a", Version: "1.0.0", Digest: digestOf("a"), Deps: []DepSpec{dep("b", "1.0.0"), dep("b", "1.0.0")}}, ErrKindParam},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Publish(tc.req)
			mustKind(t, err, tc.want)
		})
	}
}

func TestPublishMissingDependency(t *testing.T) {
	s, _ := NewService("")
	_, err := s.Publish(PublishRequest{
		RequestID: "r1", Name: "app", Version: "1.0.0", Digest: digestOf("a"),
		Deps: []DepSpec{dep("ghost", "1.0.0")},
	})
	mustKind(t, err, ErrKindDependency)
}

func TestPublishSelfCycle(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "r1", "a", "1.0.0", "a")
	// 依赖自身已发布的版本是允许的（不构成环）。
	mustPublish(t, s, "r2", "a", "2.0.0", "b", dep("a", "1.0.0"))
	// 依赖正在发布的自身版本号则构成直接自环。
	_, err := s.Publish(PublishRequest{
		RequestID: "r3", Name: "a", Version: "3.0.0", Digest: digestOf("c"),
		Deps: []DepSpec{dep("a", "3.0.0")},
	})
	mustKind(t, err, ErrKindDependency)
}

func TestPublishDigestConflictAndImmutable(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "r1", "a", "1.0.0", "a")

	// 同名同版本不同摘要：违反不可变性。
	_, err := s.Publish(PublishRequest{RequestID: "r2", Name: "a", Version: "1.0.0", Digest: digestOf("b")})
	mustKind(t, err, ErrKindDigest)

	// 完全相同的重复发布（新请求号）：内容不可变，安全返回已有版本。
	pv, err := s.Publish(PublishRequest{RequestID: "r3", Name: "a", Version: "1.0.0", Digest: digestOf("a")})
	if err != nil {
		t.Fatalf("相同内容重复发布应成功: %v", err)
	}
	if pv.ID.Digest != digestOf("a") {
		t.Fatalf("返回版本摘要不正确: %s", pv.ID.Digest)
	}
}

func TestPublishIdempotency(t *testing.T) {
	s, _ := NewService("")
	first := mustPublish(t, s, "req-1", "a", "1.0.0", "a")

	// 同号同内容：返回首次结果，不产生新版本。
	again, err := s.Publish(PublishRequest{RequestID: "req-1", Name: "a", Version: "1.0.0", Digest: digestOf("a")})
	if err != nil {
		t.Fatalf("幂等重放应成功: %v", err)
	}
	if again.Seq != first.Seq {
		t.Fatalf("幂等重放产生了新版本: seq %d != %d", again.Seq, first.Seq)
	}

	// 同号异内容：幂等冲突。
	_, err = s.Publish(PublishRequest{RequestID: "req-1", Name: "a", Version: "1.0.0", Digest: digestOf("b")})
	mustKind(t, err, ErrKindIdempotency)
}

// buildChain 构造 app -> lib -> bad 的依赖链。
func buildChain(t *testing.T, s *Service) (app, lib, bad PackageID) {
	t.Helper()
	bad = mustPublish(t, s, "p-bad", "bad", "1.0.0", "1").ID
	lib = mustPublish(t, s, "p-lib", "lib", "1.0.0", "2", dep("bad", "1.0.0")).ID
	app = mustPublish(t, s, "p-app", "app", "1.0.0", "3", dep("lib", "1.0.0")).ID
	return
}

func TestQuarantinePropagatesAlongDependencyGraph(t *testing.T) {
	s, _ := NewService("")
	app, lib, bad := buildChain(t, s)

	rec, err := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "CVE-2026-0001"})
	if err != nil {
		t.Fatalf("隔离失败: %v", err)
	}
	if !rec.Active {
		t.Fatal("隔离记录应处于生效状态")
	}

	res, err := s.Resolve("app")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if res.Selected != nil {
		t.Fatalf("被隔离波及的版本不应被选中: %s", res.Selected.ID)
	}
	if len(res.Excluded) != 1 {
		t.Fatalf("应有一条排除记录: %+v", res.Excluded)
	}
	ex := res.Excluded[0]
	if ex.Package != app {
		t.Fatalf("被排除版本应为 app: %s", ex.Package)
	}
	// 可解释路径：app -> lib -> bad。
	wantPath := []PackageID{app, lib, bad}
	if len(ex.Path) != len(wantPath) {
		t.Fatalf("解释路径长度不正确: %v", ex.Path)
	}
	for i, p := range wantPath {
		if ex.Path[i] != p {
			t.Fatalf("解释路径第 %d 段应为 %s，实际 %s", i, p, ex.Path[i])
		}
	}
	if ex.QuarantineID != rec.ID {
		t.Fatalf("排除记录应指向隔离单 %s，实际 %s", rec.ID, ex.QuarantineID)
	}
}

func TestResolvePicksHighestCleanVersion(t *testing.T) {
	s, _ := NewService("")
	_, _, bad := buildChain(t, s)
	if _, err := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"}); err != nil {
		t.Fatal(err)
	}

	// 修复链：bad 1.0.1 -> lib 1.0.1 -> app 1.0.1。
	mustPublish(t, s, "p-bad2", "bad", "1.0.1", "4")
	mustPublish(t, s, "p-lib2", "lib", "1.0.1", "5", dep("bad", "1.0.1"))
	clean := mustPublish(t, s, "p-app2", "app", "1.0.1", "6", dep("lib", "1.0.1"))

	res, err := s.Resolve("app")
	if err != nil {
		t.Fatal(err)
	}
	if res.Selected == nil || res.Selected.ID != clean.ID {
		t.Fatalf("应选中干净的最高版本: %+v", res.Selected)
	}
	if len(res.Closure) != 2 { // lib@1.0.1, bad@1.0.1
		t.Fatalf("传递闭包不正确: %v", res.Closure)
	}
	if len(res.Excluded) != 1 {
		t.Fatalf("被污染版本应出现在排除列表: %+v", res.Excluded)
	}
}

func TestSecurityRevisionAndSnapshot(t *testing.T) {
	s, _ := NewService("")
	_, _, bad := buildChain(t, s)
	if s.SecurityRevision() != 0 {
		t.Fatalf("初始修订号应为 0，实际 %d", s.SecurityRevision())
	}

	rec, _ := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"})
	if s.SecurityRevision() != 1 {
		t.Fatalf("隔离后修订号应为 1，实际 %d", s.SecurityRevision())
	}

	res, err := s.Resolve("app")
	if err != nil {
		t.Fatal(err)
	}
	if res.SecurityRevision != 1 {
		t.Fatalf("解析结果应携带快照修订号 1，实际 %d", res.SecurityRevision)
	}

	if _, err := s.LiftQuarantine(LiftRequest{RequestID: "l1", QuarantineID: rec.ID}); err != nil {
		t.Fatal(err)
	}
	if s.SecurityRevision() != 2 {
		t.Fatalf("解除后修订号应为 2，实际 %d", s.SecurityRevision())
	}

	// 幂等重放不再递增修订号。
	if _, err := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LiftQuarantine(LiftRequest{RequestID: "l1", QuarantineID: rec.ID}); err != nil {
		t.Fatal(err)
	}
	if s.SecurityRevision() != 2 {
		t.Fatalf("幂等重放不应改变修订号，实际 %d", s.SecurityRevision())
	}
}

func TestLiftDoesNotRestoreVersionsStillAffected(t *testing.T) {
	s, _ := NewService("")
	_, _, bad := buildChain(t, s)

	q1, _ := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "第一起安全事件"})
	q2, _ := s.Quarantine(QuarantineRequest{RequestID: "q2", Target: bad, Reason: "第二起安全事件"})

	// 解除其中一条：版本仍被另一条隔离路径影响。
	if _, err := s.LiftQuarantine(LiftRequest{RequestID: "l1", QuarantineID: q1.ID}); err != nil {
		t.Fatal(err)
	}
	res, err := s.Resolve("app")
	if err != nil {
		t.Fatal(err)
	}
	if res.Selected != nil {
		t.Fatalf("仍被隔离单 %s 影响，不应恢复", q2.ID)
	}
	if res.Excluded[0].QuarantineID != q2.ID {
		t.Fatalf("排除应归因于仍生效的隔离单 %s，实际 %s", q2.ID, res.Excluded[0].QuarantineID)
	}

	// 全部解除后才恢复。
	if _, err := s.LiftQuarantine(LiftRequest{RequestID: "l2", QuarantineID: q2.ID}); err != nil {
		t.Fatal(err)
	}
	res, err = s.Resolve("app")
	if err != nil {
		t.Fatal(err)
	}
	if res.Selected == nil {
		t.Fatal("全部隔离解除后应可解析")
	}
}

func TestQuarantineAndLiftErrors(t *testing.T) {
	s, _ := NewService("")
	_, _, bad := buildChain(t, s)

	// 目标不存在。
	missing := bad
	missing.Version = "9.9.9"
	_, err := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: missing, Reason: "r"})
	mustKind(t, err, ErrKindNotFound)

	// 缺少原因。
	_, err = s.Quarantine(QuarantineRequest{RequestID: "q2", Target: bad})
	mustKind(t, err, ErrKindParam)

	rec, _ := s.Quarantine(QuarantineRequest{RequestID: "q3", Target: bad, Reason: "r"})

	// 幂等重放返回同一隔离单。
	replay, err := s.Quarantine(QuarantineRequest{RequestID: "q3", Target: bad, Reason: "r"})
	if err != nil || replay.ID != rec.ID {
		t.Fatalf("幂等重放应返回同一隔离单: %v, %+v", err, replay)
	}
	// 同号异内容冲突。
	_, err = s.Quarantine(QuarantineRequest{RequestID: "q3", Target: bad, Reason: "别的"})
	mustKind(t, err, ErrKindIdempotency)

	// 解除不存在的隔离单。
	_, err = s.LiftQuarantine(LiftRequest{RequestID: "l1", QuarantineID: "Q-999"})
	mustKind(t, err, ErrKindNotFound)

	if _, err := s.LiftQuarantine(LiftRequest{RequestID: "l2", QuarantineID: rec.ID}); err != nil {
		t.Fatal(err)
	}
	// 重复解除（新请求号）。
	_, err = s.LiftQuarantine(LiftRequest{RequestID: "l3", QuarantineID: rec.ID})
	mustKind(t, err, ErrKindState)
	// 解除的幂等重放。
	if _, err := s.LiftQuarantine(LiftRequest{RequestID: "l2", QuarantineID: rec.ID}); err != nil {
		t.Fatalf("解除的幂等重放应成功: %v", err)
	}
}

func TestLatePublishCannotBypassConfirmedQuarantine(t *testing.T) {
	s, _ := NewService("")
	_, _, bad := buildChain(t, s)
	if _, err := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"}); err != nil {
		t.Fatal(err)
	}

	// 迟到发布：试图发布依赖被隔离版本的新版本，必须失败。
	_, err := s.Publish(PublishRequest{
		RequestID: "late", Name: "app", Version: "2.0.0", Digest: digestOf("7"),
		Deps: []DepSpec{dep("lib", "1.0.0")},
	})
	mustKind(t, err, ErrKindDependency)

	// 直接依赖被隔离目标同样失败。
	_, err = s.Publish(PublishRequest{
		RequestID: "late2", Name: "app", Version: "3.0.0", Digest: digestOf("8"),
		Deps: []DepSpec{dep("bad", "1.0.0")},
	})
	mustKind(t, err, ErrKindDependency)
}

func TestImpactReport(t *testing.T) {
	s, _ := NewService("")
	app, lib, bad := buildChain(t, s)
	rec, _ := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"})

	report, err := s.Impact(bad)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Quarantines) != 1 || report.Quarantines[0].ID != rec.ID {
		t.Fatalf("影响报告应包含隔离单: %+v", report.Quarantines)
	}
	// 波及 bad 自身、lib、app 三个版本。
	got := map[PackageID]bool{}
	for _, ex := range report.Affected {
		got[ex.Package] = true
	}
	for _, want := range []PackageID{bad, lib, app} {
		if !got[want] {
			t.Fatalf("影响报告缺少被波及版本 %s", want)
		}
	}

	// 未隔离的版本没有波及面。
	clean := mustPublish(t, s, "p-clean", "clean", "1.0.0", "9").ID
	report, err = s.Impact(clean)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Affected) != 0 || len(report.Quarantines) != 0 {
		t.Fatalf("未隔离版本不应有波及面: %+v", report)
	}
}

func TestResolveUnknownPackage(t *testing.T) {
	s, _ := NewService("")
	_, err := s.Resolve("ghost")
	mustKind(t, err, ErrKindNotFound)
	_, err = s.Resolve("")
	mustKind(t, err, ErrKindParam)
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewService(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, bad := buildChain(t, s)
	rec, _ := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"})

	// 重新加载：图关系、隔离状态、修订号、审计历史都应保留。
	s2, err := NewService(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.SecurityRevision() != 1 {
		t.Fatalf("重启后修订号应为 1，实际 %d", s2.SecurityRevision())
	}
	res, err := s2.Resolve("app")
	if err != nil {
		t.Fatal(err)
	}
	if res.Selected != nil || len(res.Excluded) != 1 {
		t.Fatalf("重启后隔离传播应仍然生效: %+v", res)
	}
	if len(s2.AuditLog()) != 4 { // 3 次发布 + 1 次隔离
		t.Fatalf("审计历史应保留 4 条，实际 %d", len(s2.AuditLog()))
	}

	// 重启后幂等重放仍然有效，且不产生副作用。
	replay, err := s2.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"})
	if err != nil || replay.ID != rec.ID {
		t.Fatalf("重启后幂等重放失败: %v, %+v", err, replay)
	}
	if s2.SecurityRevision() != 1 {
		t.Fatal("幂等重放不应改变修订号")
	}
	_, err = s2.Publish(PublishRequest{RequestID: "q1", Name: "x", Version: "1.0.0", Digest: digestOf("a")})
	mustKind(t, err, ErrKindIdempotency)
}

func TestConcurrentPublishQuarantineResolve(t *testing.T) {
	s, _ := NewService("")
	_, _, bad := buildChain(t, s)

	// 预备一批干净版本，供并发发布依赖。
	mustPublish(t, s, "p-ok", "ok", "1.0.0", "f")

	var wg sync.WaitGroup
	errs := make(chan error, 256)

	// 并发解析：确认隔离后，解析结果绝不能选中被波及的版本。
	quarantined := make(chan struct{})
	stop := make(chan struct{})
	var resolveWg sync.WaitGroup
	for i := 0; i < 4; i++ {
		resolveWg.Add(1)
		go func() {
			defer resolveWg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				res, err := s.Resolve("app")
				if err != nil {
					errs <- err
					return
				}
				select {
				case <-quarantined:
					if res.Selected != nil && res.Selected.ID.Version == "1.0.0" {
						errs <- fmt.Errorf("隔离确认后仍解析到被波及版本 %s", res.Selected.ID)
						return
					}
				default:
				}
			}
		}()
	}

	// 隔离 bad@1.0.0。
	if _, err := s.Quarantine(QuarantineRequest{RequestID: "q1", Target: bad, Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	close(quarantined)

	// 并发迟到发布：依赖被隔离版本的必须失败，干净版本的必须成功。
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dirty := i%2 == 0
			req := PublishRequest{
				RequestID: fmt.Sprintf("late-%d", i),
				Name:      fmt.Sprintf("pkg-%d", i),
				Version:   "1.0.0",
				Digest:    digestOf("e"),
			}
			if dirty {
				req.Deps = []DepSpec{dep("lib", "1.0.0")}
			} else {
				req.Deps = []DepSpec{dep("ok", "1.0.0")}
			}
			_, err := s.Publish(req)
			if dirty {
				if k, ok := KindOf(err); !ok || k != ErrKindDependency {
					errs <- fmt.Errorf("迟到发布应被隔离拦截，实际 %v", err)
				}
			} else if err != nil {
				errs <- fmt.Errorf("干净发布应成功，实际 %v", err)
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	resolveWg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
