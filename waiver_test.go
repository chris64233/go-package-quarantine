package packagequarantine

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock 是可手动推进的测试时钟。
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

func newFakeService(t *testing.T) (*Service, *fakeClock) {
	t.Helper()
	c := &fakeClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	s, err := NewService("", WithClock(c))
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func grantWaiverReq(reqID string, target Version, reason string, from, until time.Time, approver string) WaiverRequest {
	return WaiverRequest{
		RequestID:  reqID,
		Target:     target,
		RiskReason: reason,
		ValidFrom:  from,
		ValidUntil: until,
		Approval:   Approval{By: approver, ID: "CAB-" + reqID},
		Reason:     "deployment window",
	}
}

func TestMultipleQuarantineReasonsStackIndependently(t *testing.T) {
	s, _ := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")

	// 同一版本叠加两条不同原因的隔离。
	if _, err := s.Quarantine("q1", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Quarantine("q2", v("lib", "1"), "CVE-B"); err != nil {
		t.Fatal(err)
	}
	if s.SecurityRev() != 2 {
		t.Fatalf("rev = %d, want 2", s.SecurityRev())
	}

	// 相同原因重复隔离 -> 冲突；不同原因 -> 允许。
	_, err := s.Quarantine("q1-dup", v("lib", "1"), "CVE-A")
	assertKind(t, err, KindConflict)

	// 多风险时笼统 Release 必须拒绝，要求明确原因。
	_, err = s.Release("r-blanket", v("lib", "1"), "")
	assertKind(t, err, KindConflict)

	// 只解除 CVE-A，CVE-B 仍阻断。
	if _, err := s.ReleaseRisk("r-a", v("lib", "1"), "CVE-A", "patched"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Resolve("lib", "1")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("CVE-B must still block, got %v", err)
	}
	if blocked.RiskReason != "CVE-B" {
		t.Fatalf("blocking reason = %q, want CVE-B", blocked.RiskReason)
	}

	// 解除不存在的原因 -> 冲突。
	_, err = s.ReleaseRisk("r-ghost", v("lib", "1"), "CVE-A", "")
	assertKind(t, err, KindConflict)
}

func TestWaiverUnblocksExactlyOneRiskAndIsRecorded(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "pu", "util", "1")
	mustPublish(t, s, "pl", "lib", "1", dep("util", "1"))
	mustPublish(t, s, "pa", "app", "1", dep("lib", "1"))

	q, err := s.Quarantine("q", v("util", "1"), "CVE-A")
	if err != nil {
		t.Fatal(err)
	}

	// 豁免前：app -> lib -> util 被阻断。
	if _, err := s.Resolve("app", "1"); err == nil {
		t.Fatal("expected blocked before waiver")
	}

	from := c.Now().Add(-time.Hour)
	until := c.Now().Add(24 * time.Hour)
	gr, err := s.GrantWaiver(grantWaiverReq("w1", v("util", "1"), "CVE-A", from, until, "sec-alice"))
	if err != nil {
		t.Fatal(err)
	}
	if gr.Waiver.QuarantineEventSeq != q.Event.Seq {
		t.Fatalf("waiver must bind to quarantine seq=%d, got %d", q.Event.Seq, gr.Waiver.QuarantineEventSeq)
	}
	if gr.Event.RelatedSeq != q.Event.Seq {
		t.Fatalf("grant event related seq = %d", gr.Event.RelatedSeq)
	}

	// 豁免只放开 util 本身这一条风险；util 的依赖闭包恢复，app 整条链可解析。
	res, err := s.Resolve("app", "1")
	if err != nil {
		t.Fatalf("waived risk must unblock resolution: %v", err)
	}
	if len(res.Versions) != 3 {
		t.Fatalf("closure = %v", res.Versions)
	}
	if len(res.Waivers) != 1 {
		t.Fatalf("applied waivers = %+v, want 1", res.Waivers)
	}
	aw := res.Waivers[0]
	if aw.Target != v("util", "1") || aw.RiskReason != "CVE-A" ||
		aw.QuarantineEventSeq != q.Event.Seq || aw.GrantEventSeq != gr.Event.Seq {
		t.Fatalf("applied waiver mismatch: %+v", aw)
	}
	if aw.Approval.By != "sec-alice" || aw.Approval.ID != "CAB-w1" {
		t.Fatalf("approval not preserved: %+v", aw.Approval)
	}
	if !aw.ValidUntil.Equal(until) || !aw.ValidFrom.Equal(from) {
		t.Fatalf("validity window not preserved: %+v", aw)
	}
	if aw.Reason == "" {
		t.Fatal("applied waiver must carry a human-readable reason")
	}

	// 直接解析 util 本身同样带上豁免记录。
	self, err := s.Resolve("util", "1")
	if err != nil {
		t.Fatal(err)
	}
	if len(self.Waivers) != 1 || self.Waivers[0].RiskReason != "CVE-A" {
		t.Fatalf("self resolution waivers = %+v", self.Waivers)
	}
}

func TestWaiverDoesNotCoverNewRiskOnSameVersion(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")

	if _, err := s.Quarantine("q1", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("lib", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(24*time.Hour), "sec-alice")); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Resolve("lib", "1"); err != nil || len(r.Waivers) != 1 {
		t.Fatalf("CVE-A waived, resolution should succeed: %+v %v", r, err)
	}

	// 同一版本后来叠加新的风险原因：旧豁免不能覆盖，仍须阻断。
	if _, err := s.Quarantine("q2", v("lib", "1"), "CVE-B"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Resolve("lib", "1")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("new risk must block despite old waiver, got %v", err)
	}
	if blocked.RiskReason != "CVE-B" {
		t.Fatalf("blocking reason = %q, want CVE-B", blocked.RiskReason)
	}
}

func TestWaiverDoesNotFollowRequarantinedSameReason(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")

	q1, _ := s.Quarantine("q1", v("lib", "1"), "CVE-A")
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("lib", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(24*time.Hour), "sec-alice")); err != nil {
		t.Fatal(err)
	}
	// 风险解除后，旧豁免失效；再以相同原因重新隔离是一条全新的风险事件。
	if _, err := s.ReleaseRisk("r1", v("lib", "1"), "CVE-A", "thought fixed"); err != nil {
		t.Fatal(err)
	}
	q2, err := s.Quarantine("q2", v("lib", "1"), "CVE-A")
	if err != nil {
		t.Fatal(err)
	}
	if q2.Event.Seq == q1.Event.Seq {
		t.Fatal("re-quarantine must be a new event")
	}
	_, err = s.Resolve("lib", "1")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("old waiver must not cover the new quarantine event, got %v", err)
	}
	if blocked.QuarantineEventSeq != q2.Event.Seq {
		t.Fatalf("blocking event seq = %d, want %d", blocked.QuarantineEventSeq, q2.Event.Seq)
	}

	// 针对新事件的豁免需要重新申请；原豁免已随解除失效，可直接重新授予。
	if _, err := s.GrantWaiver(grantWaiverReq("w2", v("lib", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(time.Hour), "sec-bob")); err != nil {
		t.Fatalf("re-grant for new risk should succeed: %v", err)
	}
	if r, err := s.Resolve("lib", "1"); err != nil || len(r.Waivers) != 1 {
		t.Fatalf("new waiver should unblock: %+v %v", r, err)
	}
}

func TestWaiverExpirationBoundaries(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}

	from := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	until := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("lib", "1"), "CVE-A", from, until, "sec-alice")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		now     time.Time
		blocked bool
	}{
		{"before valid_from", from.Add(-time.Minute), true},
		{"at valid_from (inclusive)", from, false},
		{"within window", from.Add(time.Hour), false},
		{"just before valid_until", until.Add(-time.Nanosecond), false},
		{"at valid_until (exclusive)", until, true},
		{"after expiry", until.Add(time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c.t = tc.now
			res, err := s.Resolve("lib", "1")
			if tc.blocked {
				var blocked *BlockedError
				if !errors.As(err, &blocked) {
					t.Fatalf("want blocked at %s, got res=%+v", tc.now, res)
				}
				if blocked.RiskReason != "CVE-A" {
					t.Fatalf("reason = %q", blocked.RiskReason)
				}
			} else if err != nil {
				t.Fatalf("want allowed at %s, got %v", tc.now, err)
			} else if len(res.Waivers) != 1 {
				t.Fatalf("allowed resolution must record the waiver, got %+v", res.Waivers)
			}
		})
	}
}

func TestExpiredWaiverCanBeReplacedAndRevokedWaiverBlocks(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}

	until := c.Now().Add(time.Hour)
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("lib", "1"), "CVE-A",
		c.Now().Add(-time.Hour), until, "sec-alice")); err != nil {
		t.Fatal(err)
	}

	// 未到期时重复授予 -> 冲突。
	_, err := s.GrantWaiver(grantWaiverReq("w2", v("lib", "1"), "CVE-A",
		c.Now(), c.Now().Add(2*time.Hour), "sec-bob"))
	assertKind(t, err, KindConflict)

	// 撤销后立即阻断，即使仍在有效期内。
	if _, err := s.RevokeWaiver("rv1", v("lib", "1"), "CVE-A", "emergency stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve("lib", "1"); err == nil {
		t.Fatal("revoked waiver must block immediately")
	}

	// 撤销后可重新授予。
	if _, err := s.GrantWaiver(grantWaiverReq("w3", v("lib", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(time.Hour), "sec-bob")); err != nil {
		t.Fatalf("re-grant after revoke: %v", err)
	}
	if _, err := s.Resolve("lib", "1"); err != nil {
		t.Fatalf("re-granted waiver should allow: %v", err)
	}

	// 到期后无需撤销即可被新批准取代。
	c.t = until.Add(time.Hour)
	gr, err := s.GrantWaiver(grantWaiverReq("w4", v("lib", "1"), "CVE-A",
		c.Now(), c.Now().Add(time.Hour), "sec-carol"))
	if err != nil {
		t.Fatalf("expired waiver should be replaceable: %v", err)
	}
	if gr.Replayed {
		t.Fatal("replacement grant must be a new event")
	}

	// 撤销不存在的豁免 -> 冲突。
	_, err = s.RevokeWaiver("rv-missing", v("lib", "1"), "CVE-OTHER", "")
	assertKind(t, err, KindConflict)
}

func TestWaiverRevokeExpiredIsAudited(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("lib", "1"), "CVE-A",
		c.Now().Add(-2*time.Hour), c.Now().Add(-time.Hour), "sec-alice")); err != nil {
		t.Fatal(err)
	}
	// 已到期：解析阻断。
	if _, err := s.Resolve("lib", "1"); err == nil {
		t.Fatal("expired waiver must block")
	}
	// 仍可显式撤销并留痕。
	rv, err := s.RevokeWaiver("rv1", v("lib", "1"), "CVE-A", "cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Event.RelatedSeq == 0 || rv.Event.Kind != OpWaiverRevoke {
		t.Fatalf("revoke event must link the grant: %+v", rv.Event)
	}
	events := s.Snapshot().AuditEvents()
	last := events[len(events)-1]
	if last.Kind != OpWaiverRevoke {
		t.Fatalf("last event = %s", last.Kind)
	}
}

func TestWaiverIdempotencyReplayAndConflict(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	req := grantWaiverReq("w1", v("lib", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(time.Hour), "sec-alice")
	first, err := s.GrantWaiver(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.GrantWaiver(req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.Event.Seq != first.Event.Seq {
		t.Fatalf("replay must return same event: %+v vs %+v", first.Event, second.Event)
	}
	if s.SecurityRev() != 2 {
		t.Fatalf("rev = %d, replay must not bump rev", s.SecurityRev())
	}

	// 同号改有效期 -> 冲突。
	tampered := req
	tampered.ValidUntil = req.ValidUntil.Add(time.Hour)
	_, err = s.GrantWaiver(tampered)
	assertKind(t, err, KindIdempotent)

	// 同号跨操作类型 -> 冲突。
	_, err = s.RevokeWaiver("w1", v("lib", "1"), "CVE-A", "")
	assertKind(t, err, KindIdempotent)

	// 撤销幂等：同号同内容重放，不重复推进修订号。
	revBefore := s.SecurityRev()
	rv1, err := s.RevokeWaiver("rv1", v("lib", "1"), "CVE-A", "stop")
	if err != nil {
		t.Fatal(err)
	}
	rv2, err := s.RevokeWaiver("rv1", v("lib", "1"), "CVE-A", "stop")
	if err != nil {
		t.Fatal(err)
	}
	if !rv2.Replayed || rv2.Event.Seq != rv1.Event.Seq {
		t.Fatalf("revoke replay mismatch: %+v %+v", rv1.Event, rv2.Event)
	}
	if s.SecurityRev() != revBefore+1 {
		t.Fatalf("rev = %d, want %d", s.SecurityRev(), revBefore+1)
	}
}

func TestWaiverValidation(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")

	base := func() WaiverRequest {
		return grantWaiverReq("w1", v("lib", "1"), "CVE-A",
			c.Now(), c.Now().Add(time.Hour), "sec-alice")
	}

	// 无对应风险 -> 冲突。
	_, err := s.GrantWaiver(base())
	assertKind(t, err, KindConflict)

	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*WaiverRequest)
	}{
		{"missing request id", func(r *WaiverRequest) { r.RequestID = "" }},
		{"missing approver", func(r *WaiverRequest) { r.Approval.By = "" }},
		{"zero valid_from", func(r *WaiverRequest) { r.ValidFrom = time.Time{} }},
		{"until before from", func(r *WaiverRequest) { r.ValidUntil = r.ValidFrom.Add(-time.Hour) }},
		{"bad digest", func(r *WaiverRequest) { r.Target.Digest = digest("other") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base()
			tc.mutate(&req)
			_, err := s.GrantWaiver(req)
			if err == nil {
				t.Fatal("want error")
			}
			if tc.name == "bad digest" {
				assertKind(t, err, KindDigest)
			} else {
				assertKind(t, err, KindInvalidParam)
			}
		})
	}

	// 目标版本不存在。
	missing := base()
	missing.Target = v("ghost", "1")
	_, err = s.GrantWaiver(missing)
	assertKind(t, err, KindNotFound)
}

func TestSnapshotPinsWaiverStateAcrossChanges(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("lib", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(24*time.Hour), "sec-alice")); err != nil {
		t.Fatal(err)
	}

	// 旧快照固定在豁免有效状态。
	snap := s.Snapshot()

	// 快照之后：撤销豁免、叠加新风险、再解除……旧快照一律看不见。
	if _, err := s.RevokeWaiver("rv1", v("lib", "1"), "CVE-A", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Quarantine("q2", v("lib", "1"), "CVE-B"); err != nil {
		t.Fatal(err)
	}
	if r, err := snap.Resolve("lib", "1"); err != nil {
		t.Fatalf("pinned snapshot must still see the valid waiver: %v", err)
	} else if len(r.Waivers) != 1 {
		t.Fatalf("pinned waiver = %+v", r.Waivers)
	}

	// 新快照反映撤销后的现实：阻断。
	if _, err := s.Snapshot().Resolve("lib", "1"); err == nil {
		t.Fatal("new snapshot must block after revocation + new risk")
	}
}

func TestExpiryDuringInProgressResolutionCannotReturnStaleVersion(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "pu", "util", "1")
	mustPublish(t, s, "pl", "lib", "1", dep("util", "1"))
	if _, err := s.Quarantine("q", v("util", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	// 豁免在 T 时刻到期。
	expiry := c.Now().Add(time.Hour)
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("util", "1"), "CVE-A",
		c.Now(), expiry, "sec-alice")); err != nil {
		t.Fatal(err)
	}

	// 解析入口时钟已到/超过到期点：即使整次解析“进行中”时钟继续推进，
	// 也绝不能返回失效版本。模拟入口恰好等于到期时刻（边界即失效）。
	c.t = expiry
	_, err := s.Resolve("lib", "1")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("resolution starting at expiry must be blocked, got %v", err)
	}
	if blocked.Quarantined != v("util", "1") {
		t.Fatalf("blocked target = %+v", blocked.Quarantined)
	}

	// 入口尚在有效期：采样一次时钟后不受后续推进影响（一次解析一个时间基准）。
	c.t = expiry.Add(-time.Nanosecond)
	res, err := s.Resolve("lib", "1")
	if err != nil {
		t.Fatalf("resolution starting within window must succeed: %v", err)
	}
	if len(res.Waivers) != 1 {
		t.Fatalf("waiver = %+v", res.Waivers)
	}
}

func TestConcurrentWaiverChangesAndResolvesAreCoherent(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "p", "lib", "1")
	if _, err := s.Quarantine("q", v("lib", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}

	const n = 60
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	var grants, revokes, conflicts, replays int

	// 并发授予（同一请求号 n 次）：恰好一次生效。
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			res, err := s.GrantWaiver(grantWaiverReq("only-grant", v("lib", "1"), "CVE-A",
				c.Now().Add(-time.Hour), c.Now().Add(time.Hour), "sec-alice"))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && res.Replayed:
				replays++
			case err == nil:
				grants++
			case ErrorAs(err).Kind == KindConflict:
				conflicts++
			default:
				t.Errorf("unexpected grant error: %v", err)
			}
		}()
	}
	// 并发撤销（另一请求号 n 次）：要么与授予交错（撤销成功），要么无豁免可撤（冲突）。
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			res, err := s.RevokeWaiver("only-revoke", v("lib", "1"), "CVE-A", "")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && res.Replayed:
				replays++
			case err == nil:
				revokes++
			case ErrorAs(err).Kind == KindConflict:
				conflicts++
			default:
				t.Errorf("unexpected revoke error: %v", err)
			}
		}()
	}
	// 并发解析：基于某个快照修订，结果必须与该修订自洽（err 与 waivers 不矛盾）。
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			res, err := s.Resolve("lib", "1")
			if err == nil && len(res.Waivers) == 0 {
				t.Errorf("successful resolution of quarantined version must cite a waiver")
			}
			var blocked *BlockedError
			if err != nil && !errors.As(err, &blocked) {
				t.Errorf("unexpected resolve error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if grants != 1 {
		t.Fatalf("grants = %d, want exactly 1", grants)
	}
	if revokes > 1 {
		t.Fatalf("revokes = %d, want <= 1", revokes)
	}
	if grants+replays+revokes+conflicts != 2*n {
		t.Fatalf("counts don't add up: grants=%d replays=%d revokes=%d conflicts=%d",
			grants, replays, revokes, conflicts)
	}
}

func TestWaiversArePersistedAndRestored(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}

	s, err := NewService(dir, WithClock(c))
	if err != nil {
		t.Fatal(err)
	}
	mustPublish(t, s, "pu", "util", "1")
	mustPublish(t, s, "pa", "app", "1", dep("util", "1"))
	q, _ := s.Quarantine("q", v("util", "1"), "CVE-A")
	if _, err := s.Quarantine("q2", v("util", "1"), "CVE-B"); err != nil {
		t.Fatal(err)
	}
	gr, err := s.GrantWaiver(grantWaiverReq("w1", v("util", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(24*time.Hour), "sec-alice"))
	if err != nil {
		t.Fatal(err)
	}
	// CVE-B 未豁免：即便重启后 app 仍应被阻断。
	if _, err := s.Resolve("app", "1"); err == nil {
		t.Fatal("CVE-B must block before restore")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := NewService(dir, WithClock(c))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	// 风险叠加与豁免状态均还原。
	_, err = s2.Resolve("app", "1")
	var blocked *BlockedError
	if !errors.As(err, &blocked) || blocked.RiskReason != "CVE-B" {
		t.Fatalf("after restore want blocked by CVE-B, got %v", err)
	}
	ws := s2.Snapshot().Waivers()
	if len(ws) != 1 {
		t.Fatalf("restored waivers = %+v", ws)
	}
	if ws[0].QuarantineEventSeq != q.Event.Seq || ws[0].GrantEventSeq != gr.Event.Seq ||
		ws[0].Approval.By != "sec-alice" || ws[0].RiskReason != "CVE-A" {
		t.Fatalf("restored waiver mismatch: %+v", ws[0])
	}

	// 解除 CVE-B 后，仅靠豁免的 CVE-A 即可解析，且采用原因被记录。
	if _, err := s2.ReleaseRisk("r-b", v("util", "1"), "CVE-B", ""); err != nil {
		t.Fatal(err)
	}
	res, err := s2.Resolve("app", "1")
	if err != nil {
		t.Fatalf("app should resolve under waiver after restore: %v", err)
	}
	if len(res.Waivers) != 1 || res.Waivers[0].GrantEventSeq != gr.Event.Seq {
		t.Fatalf("restored applied waiver = %+v", res.Waivers)
	}

	// 到期后阻断（时钟由外部注入，跨重启仍生效）。
	c.t = gr.Waiver.ValidUntil
	if _, err := s2.Resolve("app", "1"); err == nil {
		t.Fatal("expired waiver must block after restore")
	}

	// 豁免撤销幂等记录也被回放。
	rv, err := s2.RevokeWaiver("rv-new", v("util", "1"), "CVE-A", "")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Replayed {
		t.Fatal("first revoke must apply")
	}
}

func TestImpactReportsRiskStackAndWaiverState(t *testing.T) {
	s, c := newFakeService(t)
	mustPublish(t, s, "pu", "util", "1")
	mustPublish(t, s, "pa", "app", "1", dep("util", "1"))
	if _, err := s.Quarantine("q1", v("util", "1"), "CVE-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Quarantine("q2", v("util", "1"), "CVE-B"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantWaiver(grantWaiverReq("w1", v("util", "1"), "CVE-A",
		c.Now().Add(-time.Hour), c.Now().Add(time.Hour), "sec-alice")); err != nil {
		t.Fatal(err)
	}

	rep, err := s.Impact("util", "1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DirectlyQuarantined {
		t.Fatal("util should be directly quarantined")
	}
	if rep.QuarantineEventSeq != 0 {
		t.Fatalf("with multiple risks seq should be 0 (ambiguous), got %d", rep.QuarantineEventSeq)
	}
	if len(rep.Risks) != 2 {
		t.Fatalf("risks = %+v", rep.Risks)
	}
	status := map[string]RiskStatus{}
	for _, r := range rep.Risks {
		status[r.Reason] = r
	}
	if !status["CVE-A"].Waived || status["CVE-A"].WaiverGrantEventSeq == 0 {
		t.Fatalf("CVE-A should be waived: %+v", status["CVE-A"])
	}
	if status["CVE-B"].Waived {
		t.Fatalf("CVE-B must not be waived: %+v", status["CVE-B"])
	}
	// CVE-B 未豁免：app 仍被阻断。
	for _, e := range rep.Affected {
		if e.Version.key() == "app@1" && !e.Blocked {
			t.Fatal("app should be reported blocked via unwaived CVE-B")
		}
	}

	// 豁免到期后，影响查询同步反映。
	c.t = c.Now().Add(2 * time.Hour)
	rep, _ = s.Impact("util", "1")
	for _, r := range rep.Risks {
		if r.Reason == "CVE-A" && r.Waived {
			t.Fatal("CVE-A waiver must be reported inactive after expiry")
		}
	}
	if fmt.Sprint(rep.Affected[0].Blocked) != "true" {
		t.Fatal("app should be blocked after waiver expiry")
	}
}
