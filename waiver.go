package packagequarantine

import (
	"strings"
	"time"
)

// Approval 记录豁免的批准信息：谁批准、依据哪张批准单（工单/CAB 记录等）。
type Approval struct {
	By string `json:"by"` // 批准人/批准角色，必填
	ID string `json:"id"` // 批准单号（可选但建议填写，便于审计回溯）
}

// Waiver 是一条有期限的风险豁免：经批准后临时放开【某具体版本】上
// 【某一条隔离原因对应的那一条隔离事件】。
//
// 豁免的匹配是四元组全等：
// (Target, RiskReason, QuarantineEventSeq, 有效期)。
// 因此：
//   - 同一版本后来出现新的隔离原因：本豁免不覆盖（RiskReason 不同）；
//   - 旧风险解除后又以相同原因重新隔离：本豁免不覆盖（QuarantineEventSeq 不同）；
//   - 豁免到期或被撤销：不再生效，解析照常阻断。
type Waiver struct {
	Target             Version
	RiskReason         string
	QuarantineEventSeq int // 被豁免的具体隔离事件序号
	GrantEventSeq      int // 豁免授予事件序号
	ValidFrom          time.Time
	ValidUntil         time.Time
	Approval           Approval
}

// waiverKey 是豁免在内存中的键：精确到“版本 + 隔离原因”。
func waiverKey(target Version, riskReason string) string {
	return target.key() + "\x00" + riskReason
}

// validAt 报告 t 时刻豁免是否处于有效期内：[ValidFrom, ValidUntil)，
// 到期时刻本身即失效。
func (w *Waiver) validAt(t time.Time) bool {
	return !t.Before(w.ValidFrom) && t.Before(w.ValidUntil)
}

// Active 报告豁免在当前时钟下是否有效（便捷查询用）。
func (w *Waiver) Active(now time.Time) bool { return w.validAt(now.UTC()) }

// waiverDetail 是豁免在审计事件中的可持久化形态。
type WaiverDetail struct {
	QuarantineEventSeq int       `json:"quarantine_event_seq"`
	ValidFrom          time.Time `json:"valid_from"`
	ValidUntil         time.Time `json:"valid_until"`
	ApprovedBy         string    `json:"approved_by"`
	ApprovalID         string    `json:"approval_id"`
}

func waiverDetailOf(w *Waiver) *WaiverDetail {
	return &WaiverDetail{
		QuarantineEventSeq: w.QuarantineEventSeq,
		ValidFrom:          w.ValidFrom,
		ValidUntil:         w.ValidUntil,
		ApprovedBy:         w.Approval.By,
		ApprovalID:         w.Approval.ID,
	}
}

func waiverFromEvent(ev *SecurityEvent) *Waiver {
	d := ev.Waiver
	return &Waiver{
		Target:             ev.Target,
		RiskReason:         ev.RiskReason,
		QuarantineEventSeq: d.QuarantineEventSeq,
		GrantEventSeq:      ev.Seq,
		ValidFrom:          d.ValidFrom,
		ValidUntil:         d.ValidUntil,
		Approval: Approval{
			By: d.ApprovedBy,
			ID: d.ApprovalID,
		},
	}
}

// WaiverRequest 是豁免授予申请。
type WaiverRequest struct {
	RequestID  string    // 外部请求号，必填
	Target     Version   // 被豁免的具体版本（name/version/digest 必须与已发布版本一致）
	RiskReason string    // 要放开的那一条隔离原因，必须与生效隔离的原因逐字匹配
	ValidFrom  time.Time // 有效期起（含）
	ValidUntil time.Time // 有效期止（不含），必须晚于 ValidFrom
	Approval   Approval  // 批准信息，Approval.By 必填
	Reason     string    // 申请备注（为何需要临时豁免），可选
}

func (req *WaiverRequest) validate() error {
	if err := validateSecurityOp(req.RequestID, req.Target); err != nil {
		return err
	}
	if strings.TrimSpace(req.Approval.By) == "" {
		return errf(KindInvalidParam, "waiver approval approver is required")
	}
	if req.ValidFrom.IsZero() || req.ValidUntil.IsZero() {
		return errf(KindInvalidParam, "waiver valid_from and valid_until are required")
	}
	if !req.ValidUntil.After(req.ValidFrom) {
		return errf(KindInvalidParam, "waiver valid_until %s must be after valid_from %s",
			req.ValidUntil.Format(time.RFC3339), req.ValidFrom.Format(time.RFC3339))
	}
	return nil
}

// normalizedWaiverPayload 是幂等哈希用的规范化申请载荷（时间统一为 UTC）。
type normalizedWaiverPayload struct {
	Target     Version `json:"target"`
	RiskReason string  `json:"risk_reason"`
	ValidFrom  string  `json:"valid_from"`
	ValidUntil string  `json:"valid_until"`
	ApprovedBy string  `json:"approved_by"`
	ApprovalID string  `json:"approval_id"`
	Reason     string  `json:"reason"`
}

func (req *WaiverRequest) hashPayload() normalizedWaiverPayload {
	return normalizedWaiverPayload{
		Target:     req.Target,
		RiskReason: req.RiskReason,
		ValidFrom:  req.ValidFrom.UTC().Format(time.RFC3339Nano),
		ValidUntil: req.ValidUntil.UTC().Format(time.RFC3339Nano),
		ApprovedBy: req.Approval.By,
		ApprovalID: req.Approval.ID,
		Reason:     req.Reason,
	}
}

// WaiverResult 是豁免授予/撤销的结果。
type WaiverResult struct {
	Waiver   *Waiver        // 涉及的豁免（撤销后仍返回被撤销的那份快照）
	Event    *SecurityEvent // 本次生效或重放的授予/撤销事件
	Replayed bool           // 是否为同一外部请求号的重放
}

// GrantWaiver 经批准授予一条有期限的风险豁免。
//
// 目标版本必须已发布、摘要匹配，且该版本当前必须存在一条原因为 RiskReason 的
// 生效隔离；否则分别返回 KindNotFound/KindDigest/KindConflict。
//
// 同一“版本 + 风险原因”同时只允许存在一条未撤销豁免：若已有豁免当前仍处于
// 有效期（或尚未生效），返回 KindConflict，需先撤销；已到期的豁免可被新的
// 批准直接取代（旧授予事件仍保留在审计历史中）。成功后安全修订号加一。
func (s *Service) GrantWaiver(req WaiverRequest) (*WaiverResult, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	req.ValidFrom = req.ValidFrom.UTC()
	req.ValidUntil = req.ValidUntil.UTC()
	hash := payloadHash(OpWaiverGrant, req.hashPayload())

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, conflict := s.lookupRequest(req.RequestID, OpWaiverGrant, hash); conflict != nil {
		return nil, conflict
	} else if rec != nil {
		ev := s.eventBySeq(mustAtoi(rec.Ref))
		return &WaiverResult{Waiver: waiverFromEvent(ev), Event: ev, Replayed: true}, nil
	}

	pv, err := s.lookupVersion(req.Target)
	if err != nil {
		return nil, err
	}
	k := pv.Version.key()
	qEvent, ok := s.active[k][req.RiskReason]
	if !ok {
		return nil, errf(KindConflict,
			"version %s has no active quarantine with reason %q; waiver can only target an existing risk",
			k, req.RiskReason)
	}
	wk := waiverKey(pv.Version, req.RiskReason)
	if existing, ok := s.waivers[wk]; ok {
		// 未到期（含尚未生效）的豁免必须先撤销；纯已到期记录可被新批准取代。
		if s.now().Before(existing.ValidUntil) {
			return nil, errf(KindConflict,
				"waiver for %s reason %q is already granted by event seq=%d and valid until %s; revoke it first",
				k, req.RiskReason, existing.GrantEventSeq, existing.ValidUntil.Format(time.RFC3339))
		}
	}

	ev := s.newEvent(OpWaiverGrant, pv.Version, req.RequestID, req.Reason, qEvent.Seq)
	ev.RiskReason = req.RiskReason
	w := &Waiver{
		Target:             pv.Version,
		RiskReason:         req.RiskReason,
		QuarantineEventSeq: qEvent.Seq,
		GrantEventSeq:      ev.Seq, // 授予序号即事件自身序号
		ValidFrom:          req.ValidFrom,
		ValidUntil:         req.ValidUntil,
		Approval:           Approval{By: req.Approval.By, ID: req.Approval.ID},
	}
	ev.Waiver = waiverDetailOf(w)
	rec := s.newRequestRecord(req.RequestID, OpWaiverGrant, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	s.waivers[wk] = w
	return &WaiverResult{Waiver: w, Event: ev}, nil
}

// RevokeWaiver 撤销目标版本上指定风险原因的当前豁免。无论豁免是否已到期都可
// 撤销（撤销一条已到期豁免仍会记录审计事件并推进修订号）。成功后安全修订号加一。
func (s *Service) RevokeWaiver(requestID string, target Version, riskReason, note string) (*WaiverResult, error) {
	if err := validateSecurityOp(requestID, target); err != nil {
		return nil, err
	}
	hash := payloadHash(OpWaiverRevoke, struct {
		Target     Version `json:"target"`
		RiskReason string  `json:"risk_reason"`
		Note       string  `json:"note"`
	}{target, riskReason, note})

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, conflict := s.lookupRequest(requestID, OpWaiverRevoke, hash); conflict != nil {
		return nil, conflict
	} else if rec != nil {
		revokeEv := s.eventBySeq(mustAtoi(rec.Ref))
		return &WaiverResult{
			Waiver:   waiverFromEvent(s.eventBySeq(revokeEv.RelatedSeq)),
			Event:    revokeEv,
			Replayed: true,
		}, nil
	}

	pv, err := s.lookupVersion(target)
	if err != nil {
		return nil, err
	}
	wk := waiverKey(pv.Version, riskReason)
	w, ok := s.waivers[wk]
	if !ok {
		return nil, errf(KindConflict,
			"version %s has no revocable waiver for reason %q", pv.Version.key(), riskReason)
	}

	ev := s.newEvent(OpWaiverRevoke, pv.Version, requestID, note, w.GrantEventSeq)
	ev.RiskReason = riskReason
	rec := s.newRequestRecord(requestID, OpWaiverRevoke, hash, ev)
	if err := s.persistSecurity(ev, rec); err != nil {
		return nil, err
	}
	s.appendEvent(ev, rec)
	delete(s.waivers, wk)
	return &WaiverResult{Waiver: w, Event: ev}, nil
}
