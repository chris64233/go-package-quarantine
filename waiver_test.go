package packagequarantine

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// 固定时间点，便于确定性地测试到期语义。
var (
	t0      = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	tBefore = t0.Add(-time.Minute)
	tAt     = t0
	tAfter  = t0.Add(time.Minute)
)

func grantWaiver(t *testing.T, s *Service, reqID string, target Version, reason string,
	expiresAt time.Time, approver string) *WaiverGrantResult {
	t.Helper()
	res, err := s.GrantWaiver(reqID, target, reason, expiresAt, Approval{Approver: approver, Ticket: "TIC-1"})
	if err != nil {
		t.Fatalf("GrantWaiver(%s %q): %v", target.key(), reason, err)
	}
	return res
}

func TestWaiverAllowsExactlyOneRiskWithExplainableUse(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s) // util <- lib <- app

	if _, err := s.Quarantine("q-util", v("util", "1.0.0"), "CVE-2026-0001"); err != nil {
		t.Fatal(err)
	}
	// 无豁免：app 经 lib -> util 被阻塞，阻塞原因为该 CVE。
	_, err := s.Resolve("app", "1.0.0")
	var blocked *BlockedError
	if !errors.As(err, &blocked) || blocked.Reason != "CVE-2026-0001" {
		t.Fatalf("want blocked with reason CVE-2026-0001, got %v", err)
	}

	g := grantWaiver(t, s, "w-util", v("util", "1.0.0"), "CVE-2026-0001",
		time.Now().Add(time.Hour), "sec-alice")
	if g.Event.Rev != 2 || g.Waiver.QuarantineSeq != 1 || g.Waiver.Seq != 2 {
		t.Fatalf("grant event/waiver = %+v %+v", g.Event, g.Waiver)
	}

	// 有豁免：解析成功，并在结果中说明“因为哪条豁免、沿哪条路径、谁批准、何时到期”。
	res, err := s.Resolve("app", "1.0.0")
	if err != nil {
		t.Fatalf("waived risk must resolve: %v", err)
	}
	if len(res.Versions) != 3 {
		t.Fatalf("closure = %v", keys(res.Versions))
	}
	if len(res.Waivers) != 1 {
		t.Fatalf("waiver uses = %+v, want 1", res.Waivers)
	}
	use := res.Waivers[0]
	if use.Target != v("util", "1.0.0") || use.Reason != "CVE-2026-0001" ||
		use.QuarantineSeq != 1 || use.WaiverSeq != g.Waiver.Seq {
		t.Fatalf("waiver use identity = %+v", use)
	}
	if got := pathKeys(use.Path); fmt.Sprint(got) != "[app@1.0.0 lib@1.0.0 util@1.0.0]" {
		t.Fatalf("waiver use path = %v", got)
	}
	if use.Approval.Approver != "sec-alice" || use.ExpiresAt != g.Waiver.ExpiresAt {
		t.Fatalf("waiver use approval/expiry = %+v", use)
	}

	// 留痕：每次解析采用豁免都要保存采用原因。
	usage := s.WaiverUsage()
	if len(usage) != 1 || usage[0].Root != v("app", "1.0.0") ||
		len(usage[0].Uses) != 1 || usage[0].Uses[0].Reason != "CVE-2026-0001" {
		t.Fatalf("waiver usage records = %+v", usage)
	}
}

func TestWaiverDoesNotCoverNewRiskReasonOnSameVersion(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s)

	q1, err := s.Quarantine("q1", v("util", "1.0.0"), "CVE-A")
	if err != nil {
		t.Fatal(err)
	}
	grantWaiver(t, s, "w1", v("util", "1.0.0"), "CVE-A", time.Now().Add(time.Hour), "alice")

	if r, err := s.Resolve("app", "1.0.0"); err != nil {
		t.Fatalf("CVE-A waived, should resolve: %v", err)
	} else if len(r.Waivers) != 1 {
		t.Fatalf("want 1 waiver use, got %+v", r.Waivers)
	}

	// 同一版本后来出现新的隔离原因：旧豁免不能自动覆盖。
	if _, err := s.Quarantine("q2", v("util", "1.0.0"), "CVE-B"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Resolve("app", "1.0.0")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("new reason CVE-B must block despite old waiver, got %v", err)
	}
	if blocked.Reason != "CVE-B" {
		t.Fatalf("block reason = %q, want CVE-B", blocked.Reason)
	}
	if got := pathKeys(blocked.Path); fmt.Sprint(got) != "[app@1.0.0 lib@1.0.0 util@1.0.0]" {
		t.Fatalf("block path = %v", got)
	}

	// util 自身直接解析也按新原因阻断。
	_, err = s.Resolve("util", "1.0.0")
	if !errors.As(err, &blocked) || blocked.Reason != "CVE-B" {
		t.Fatalf("direct resolve should name CVE-B, got %v", err)
	}

	// 影响查询：两条原因并列，只有 CVE-A 被豁免；依赖方重新处于被排除状态。
	rep, err := s.Impact("util", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Quarantines) != 2 {
		t.Fatalf("quarantine statuses = %+v", rep.Quarantines)
	}
	waivedByReason := map[string]bool{}
	for _, st := range rep.Quarantines {
		waivedByReason[st.Reason] = st.Waived
		if st.Reason == "CVE-A" && (!st.Waived || st.WaiverSeq == 0) {
			t.Fatalf("CVE-A should show waived: %+v", st)
		}
	}
	if !waivedByReason["CVE-A"] || waivedByReason["CVE-B"] {
		t.Fatalf("waived flags = %v", waivedByReason)
	}
	for _, e := range rep.Affected {
		if !e.Blocked {
			t.Fatalf("%s must be blocked while CVE-B is open", e.Version.key())
		}
	}

	// 被阻塞的解析不得产生豁免采用留痕（只有上一次成功解析的 1 条）。
	if n := len(s.WaiverUsage()); n != 1 {
		t.Fatalf("blocked resolution must not record waiver usage, got %d records", n)
	}
	_ = q1
}

func TestWaiverDoesNotCoverSameReasonAfterQuarantineRecreated(t *testing.T) {
	// 旧隔离解除后，即便用完全相同的原因字符串重新隔离，旧豁免锁定的是旧隔离
	// 事件序号，不能覆盖新的隔离事件。
	s, _ := NewService("")
	buildChain(t, s)

	q1, _ := s.Quarantine("q1", v("util", "1.0.0"), "CVE-A")
	w1 := grantWaiver(t, s, "w1", v("util", "1.0.0"), "CVE-A", time.Now().Add(time.Hour), "alice")
	if _, err := s.Release("r1", v("util", "1.0.0"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	q2, err := s.Quarantine("q2", v("util", "1.0.0"), "CVE-A")
	if err != nil {
		t.Fatal(err)
	}
	if q2.Event.Seq == q1.Event.Seq {
		t.Fatal("re-quarantine must be a new event")
	}

	_, err = s.Resolve("app", "1.0.0")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("old waiver seq=%d must not cover new quarantine seq=%d", w1.Waiver.Seq, q2.Event.Seq)
	}
	if blocked.Reason != "CVE-A" {
		t.Fatalf("reason = %q", blocked.Reason)
	}

	// 为新隔离重新申请豁免后才能放行。
	g2 := grantWaiver(t, s, "w2", v("util", "1.0.0"), "CVE-A", time.Now().Add(time.Hour), "bob")
	if r, err := s.Resolve("app", "1.0.0"); err != nil || len(r.Waivers) != 1 ||
		r.Waivers[0].WaiverSeq != g2.Waiver.Seq || r.Waivers[0].QuarantineSeq != q2.Event.Seq {
		t.Fatalf("resolution after renewed waiver = %+v err=%v", r, err)
	}
}

func TestWaiverExpiry(t *testing.T) {
	s, _ := NewService("")
	clock := tBefore
	s.nowFn = func() time.Time { return clock }
	buildChain(t, s)
	if _, err := s.Quarantine("q", v("util", "1.0.0"), "CVE-X"); err != nil {
		t.Fatal(err)
	}
	grantWaiver(t, s, "w", v("util", "1.0.0"), "CVE-X", t0, "alice")

	// 到期前：放行，且快照记录豁免。
	snap := s.snapshotAt(tBefore)
	if r, err := snap.Resolve("app", "1.0.0"); err != nil {
		t.Fatalf("before expiry should resolve: %v", err)
	} else if len(r.Waivers) != 1 {
		t.Fatalf("waiver uses = %+v", r.Waivers)
	}
	if ws := snap.ActiveWaivers(); len(ws) != 1 || ws[0].Seq == 0 {
		t.Fatalf("active waivers before expiry = %+v", ws)
	}

	// 到期时刻本身即失效；到期后：阻断。
	for _, at := range []time.Time{tAt, tAfter} {
		snap := s.snapshotAt(at)
		_, err := snap.Resolve("app", "1.0.0")
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("at %s waiver must be expired, got resolution", at)
		}
		if blocked.Reason != "CVE-X" {
			t.Fatalf("at %s reason = %q", at, blocked.Reason)
		}
		if ws := snap.ActiveWaivers(); len(ws) != 0 {
			t.Fatalf("at %s active waivers = %+v", at, ws)
		}
	}

	// 到期后不能撤销，也不会与重新申请冲突（可以为同一风险申请一条新豁免）。
	clock = tAfter
	if _, err := s.RevokeWaiver("rv-late", v("util", "1.0.0"), "CVE-X", ""); err == nil {
		t.Fatal("revoking an expired waiver must fail")
	} else {
		assertKind(t, err, KindConflict)
	}
	grantWaiver(t, s, "w-renew", v("util", "1.0.0"), "CVE-X", tAfter.Add(time.Hour), "alice")
}

func TestWaiverRevoke(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s)
	if _, err := s.Quarantine("q", v("util", "1.0.0"), "CVE-X"); err != nil {
		t.Fatal(err)
	}
	g := grantWaiver(t, s, "w", v("util", "1.0.0"), "CVE-X", time.Now().Add(time.Hour), "alice")

	if r, err := s.Resolve("app", "1.0.0"); err != nil || len(r.Waivers) != 1 {
		t.Fatalf("pre-revoke resolution = %+v %v", r, err)
	}
	revBefore := s.SecurityRev()

	rv, err := s.RevokeWaiver("rv", v("util", "1.0.0"), "CVE-X", "approval withdrawn")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Event.Rev != revBefore+1 || rv.Event.RelatedSeq != g.Waiver.Seq ||
		rv.Event.Kind != OpRevokeWaiver {
		t.Fatalf("revoke event = %+v", rv.Event)
	}

	_, err = s.Resolve("app", "1.0.0")
	var blocked *BlockedError
	if !errors.As(err, &blocked) || blocked.Reason != "CVE-X" {
		t.Fatalf("after revoke must block with CVE-X, got %v", err)
	}

	// 撤销反映在豁免对象与审计事件上。
	if w := s.waivers[g.Waiver.Seq]; w.RevokedAt.IsZero() || w.RevokedReqID != "rv" ||
		w.RevokeEventSeq != rv.Event.Seq {
		t.Fatalf("waiver revoke state = %+v", w)
	}
	events := s.Snapshot().AuditEvents()
	last := events[len(events)-1]
	if last.Kind != OpRevokeWaiver || last.Reason != "approval withdrawn" {
		t.Fatalf("last audit event = %+v", last)
	}

	// 撤销后不能重复撤销。
	if _, err := s.RevokeWaiver("rv-again", v("util", "1.0.0"), "CVE-X", ""); err == nil {
		t.Fatal("second revoke must fail")
	} else {
		assertKind(t, err, KindConflict)
	}
}

func TestWaiverGrantValidationAndConflicts(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-1"); err != nil {
		t.Fatal(err)
	}

	approval := Approval{Approver: "alice"}
	// 缺少批准人。
	if _, err := s.GrantWaiver("w0", v("lib", "1"), "CVE-1", time.Now().Add(time.Hour), Approval{}); err == nil {
		t.Fatal("waiver without approver must fail")
	} else {
		assertKind(t, err, KindInvalidParam)
	}
	// 到期时间已过。
	if _, err := s.GrantWaiver("w0", v("lib", "1"), "CVE-1", time.Now().Add(-time.Second), approval); err == nil {
		t.Fatal("expired waiver must fail")
	} else {
		assertKind(t, err, KindInvalidParam)
	}
	// 缺少原因。
	if _, err := s.GrantWaiver("w0", v("lib", "1"), "  ", time.Now().Add(time.Hour), approval); err == nil {
		t.Fatal("waiver without reason must fail")
	} else {
		assertKind(t, err, KindInvalidParam)
	}
	// 目标不存在 / 摘要不匹配。
	if _, err := s.GrantWaiver("w0", v("ghost", "1"), "CVE-1", time.Now().Add(time.Hour), approval); err == nil {
		t.Fatal("waiver on missing version must fail")
	} else {
		assertKind(t, err, KindNotFound)
	}
	if _, err := s.GrantWaiver("w0",
		Version{Name: "lib", Version: "1", Digest: digest("wrong")},
		"CVE-1", time.Now().Add(time.Hour), approval); err == nil {
		t.Fatal("waiver with wrong digest must fail")
	} else {
		assertKind(t, err, KindDigest)
	}
	// 不存在的风险原因（该版本没有这条生效隔离）。
	if _, err := s.GrantWaiver("w0", v("lib", "1"), "CVE-OTHER", time.Now().Add(time.Hour), approval); err == nil {
		t.Fatal("waiver must reference an existing active quarantine")
	} else {
		assertKind(t, err, KindConflict)
	}

	// 成功授予。
	g := grantWaiver(t, s, "w1", v("lib", "1"), "CVE-1", time.Now().Add(time.Hour), "alice")

	// 同一风险上已有有效豁免 -> 冲突。
	if _, err := s.GrantWaiver("w2", v("lib", "1"), "CVE-1", time.Now().Add(2*time.Hour), approval); err == nil {
		t.Fatal("duplicate active waiver must conflict")
	} else {
		assertKind(t, err, KindConflict)
	}

	// 撤销后再申请新豁免允许（不同请求号）。
	if _, err := s.RevokeWaiver("rv", v("lib", "1"), "CVE-1", ""); err != nil {
		t.Fatal(err)
	}
	g2 := grantWaiver(t, s, "w3", v("lib", "1"), "CVE-1", time.Now().Add(time.Hour), "bob")
	if g2.Waiver.Seq == g.Waiver.Seq {
		t.Fatal("renewed waiver must be a new record")
	}
}

func TestWaiverIdempotencyReplayAndConflict(t *testing.T) {
	s, _ := NewService("")
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-1"); err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(time.Hour)
	ap := Approval{Approver: "alice", Ticket: "T-42"}
	first, err := s.GrantWaiver("w-1", v("lib", "1"), "CVE-1", exp, ap)
	if err != nil {
		t.Fatal(err)
	}
	// 同号同内容重放：返回同一条豁免，不推进修订号。
	second, err := s.GrantWaiver("w-1", v("lib", "1"), "CVE-1", exp, ap)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.Waiver.Seq != first.Waiver.Seq || second.Event.Seq != first.Event.Seq {
		t.Fatalf("grant replay mismatch: %+v vs %+v", first, second)
	}
	if s.SecurityRev() != 2 {
		t.Fatalf("rev = %d, replay must not bump rev", s.SecurityRev())
	}

	// 同号异内容（改到期时间/批准人/原因）-> 冲突。
	if _, err := s.GrantWaiver("w-1", v("lib", "1"), "CVE-1", exp.Add(time.Hour), ap); err == nil {
		t.Fatal("same request id with different expiry must conflict")
	} else {
		assertKind(t, err, KindIdempotent)
	}
	if _, err := s.GrantWaiver("w-1", v("lib", "1"), "CVE-1", exp,
		Approval{Approver: "mallory"}); err == nil {
		t.Fatal("same request id with different approver must conflict")
	} else {
		assertKind(t, err, KindIdempotent)
	}
	// 请求号不能跨操作类型复用。
	if _, err := s.Quarantine("w-1", v("lib", "1"), "other"); err == nil {
		t.Fatal("request id reused across op types must conflict")
	} else {
		assertKind(t, err, KindIdempotent)
	}

	// 撤销幂等：同号同内容重放，不推进修订号。
	rv, err := s.RevokeWaiver("rv-1", v("lib", "1"), "CVE-1", "note")
	if err != nil {
		t.Fatal(err)
	}
	rev := s.SecurityRev()
	rv2, err := s.RevokeWaiver("rv-1", v("lib", "1"), "CVE-1", "note")
	if err != nil {
		t.Fatal(err)
	}
	if !rv2.Replayed || rv2.Event.Seq != rv.Event.Seq {
		t.Fatalf("revoke replay mismatch: %+v vs %+v", rv2.Event, rv.Event)
	}
	if s.SecurityRev() != rev {
		t.Fatalf("rev changed on revoke replay: %d != %d", s.SecurityRev(), rev)
	}
	// 撤销请求同号异内容 -> 冲突。
	if _, err := s.RevokeWaiver("rv-1", v("lib", "1"), "CVE-1", "different note"); err == nil {
		t.Fatal("revoke same id different payload must conflict")
	} else {
		assertKind(t, err, KindIdempotent)
	}
}

func TestSnapshotPinsWaiverAcrossRevokeAndNewRisk(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s)
	if _, err := s.Quarantine("q", v("util", "1.0.0"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	grantWaiver(t, s, "w", v("util", "1.0.0"), "CVE-A", time.Now().Add(time.Hour), "alice")

	// 快照在豁免有效时取得：之后撤销豁免并新增风险，都不能影响这份快照。
	pinned := s.Snapshot()
	if _, err := s.RevokeWaiver("rv", v("util", "1.0.0"), "CVE-A", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Quarantine("q2", v("util", "1.0.0"), "CVE-B"); err != nil {
		t.Fatal(err)
	}
	if r, err := pinned.Resolve("app", "1.0.0"); err != nil {
		t.Fatalf("pinned snapshot must still resolve: %v", err)
	} else if len(r.Waivers) != 1 || r.Waivers[0].Reason != "CVE-A" {
		t.Fatalf("pinned waiver use = %+v", r.Waivers)
	}

	// 下一次请求取新快照：必须看到撤销与新风险，返回失效豁免不得放行。
	_, err := s.Snapshot().Resolve("app", "1.0.0")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatal("fresh snapshot must block after revoke + new risk")
	}
}

func TestConcurrentRevokeNeverReturnsStaleWaiver(t *testing.T) {
	s, _ := NewService("")
	buildChain(t, s)
	if _, err := s.Quarantine("q", v("util", "1.0.0"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	grantWaiver(t, s, "w", v("util", "1.0.0"), "CVE-A", time.Now().Add(time.Hour), "alice")

	const n = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	type outcome struct {
		rev     int
		allowed bool
	}
	outcomes := make([]outcome, n)

	// 一半 goroutine 反复取新快照解析，另一半撤销豁免。
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				snap := s.Snapshot()
				r, err := snap.Resolve("app", "1.0.0")
				outcomes[i] = outcome{rev: snap.Rev(), allowed: err == nil && len(r.Waivers) == 1}
				if err != nil {
					var b *BlockedError
					if !errors.As(err, &b) {
						t.Errorf("unexpected resolve error: %v", err)
					}
					outcomes[i] = outcome{rev: snap.Rev()}
				}
			} else {
				_, _ = s.RevokeWaiver(fmt.Sprintf("rv-%d", i), v("util", "1.0.0"), "CVE-A", "")
			}
		}()
	}
	close(start)
	wg.Wait()

	// 撤销只生效一次，修订号恰好再 +1（quarantine=1, grant=2, revoke=3）。
	if s.SecurityRev() != 3 {
		t.Fatalf("rev = %d, want 3", s.SecurityRev())
	}

	// 关键不变量：任何成功解析所基于的修订号必须早于撤销修订；撤销修订及之后
	// 的快照绝不允许带豁免放行（不能返回已失效的版本）。
	var revokeRev int
	for _, ev := range s.Snapshot().AuditEvents() {
		if ev.Kind == OpRevokeWaiver {
			revokeRev = ev.Rev
		}
	}
	for _, oc := range outcomes {
		if oc.allowed && oc.rev >= revokeRev {
			t.Fatalf("resolution allowed at rev %d after revoke rev %d", oc.rev, revokeRev)
		}
	}
}

func TestWaiverStackingOnDifferentNodes(t *testing.T) {
	// util 被豁免；lib 后来被另一个原因隔离：util 的豁免不能救 lib 链路上的解析。
	s, _ := NewService("")
	buildChain(t, s)
	if _, err := s.Quarantine("q-u", v("util", "1.0.0"), "CVE-U"); err != nil {
		t.Fatal(err)
	}
	grantWaiver(t, s, "w-u", v("util", "1.0.0"), "CVE-U", time.Now().Add(time.Hour), "alice")
	if _, err := s.Quarantine("q-l", v("lib", "1.0.0"), "CVE-L"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Resolve("app", "1.0.0")
	var blocked *BlockedError
	if !errors.As(err, &blocked) || blocked.Reason != "CVE-L" {
		t.Fatalf("app must block via lib CVE-L, got %v", err)
	}
	if got := pathKeys(blocked.Path); fmt.Sprint(got) != "[app@1.0.0 lib@1.0.0]" {
		t.Fatalf("path = %v", got)
	}
	// util 自身仍可凭豁免解析。
	if r, err := s.Resolve("util", "1.0.0"); err != nil || len(r.Waivers) != 1 {
		t.Fatalf("util resolution = %+v %v", r, err)
	}
}
