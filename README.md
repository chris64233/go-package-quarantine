# go-package-quarantine

软件包版本隔离服务：管理不可变的软件包版本及其依赖图，支持安全事件驱动的版本隔离，
隔离沿依赖图传播，安装解析自动排除被波及的版本并给出可解释的依赖路径。

开发环境：Go 1.23.0。

## 核心概念

- **版本坐标**：软件包版本由 `名称 + 版本号(X.Y.Z) + 内容摘要(sha256:<64 hex>)` 共同唯一确定，
  发布后不可更改；同名同版本以不同摘要再次发布会返回摘要错误。
- **依赖图**：发布时声明直接依赖（名称 + 版本号），服务端解析为确切坐标并持久化。
  依赖不存在、依赖成环（含自环）都会使发布失败。
- **隔离传播**：隔离针对某一具体版本。被隔离版本、以及任何传递依赖到它的版本，
  都会从解析结果中排除；排除记录附带从被排除版本到隔离目标的完整依赖路径。
- **安全修订号**：每次隔离 / 解除隔离都会递增安全修订号；一次解析全程只读取
  同一修订号对应的快照，结果中携带该修订号。
- **多条隔离**：同一版本可存在多条生效中的隔离记录；解除其中一条不会恢复
  仍被其他隔离路径影响的版本。
- **幂等**：发布、隔离、解除都要求外部请求号。同号同内容重放返回首次结果；
  同号异内容返回幂等冲突错误。发布、隔离、解析并发时，已确认的隔离不能被
  迟到发布绕开（发布在同一把写锁内校验依赖未被隔离波及）。
- **持久化**：图关系、隔离记录、幂等记录与审计历史以 JSON 原子写入磁盘，
  重启后完整恢复。

## API

```go
s, err := packagequarantine.NewService("state.json") // 传 "" 则仅内存

// 发布版本（不可变，依赖必须已发布且未被隔离）
pv, err := s.Publish(packagequarantine.PublishRequest{
    RequestID: "req-1",
    Name:      "app",
    Version:   "1.0.0",
    Digest:    "sha256:<64 hex>",
    Deps:      []packagequarantine.DepSpec{{Name: "lib", Version: "1.0.0"}},
})

// 隔离某一具体版本（安全修订号 +1）
rec, err := s.Quarantine(packagequarantine.QuarantineRequest{
    RequestID: "q-1", Target: pv.ID, Reason: "CVE-2026-0001",
})

// 解除一条隔离记录（安全修订号 +1）
_, err = s.LiftQuarantine(packagequarantine.LiftRequest{
    RequestID: "l-1", QuarantineID: rec.ID,
})

// 依赖解析：选中未被隔离波及的最高版本；被排除版本附带解释路径
res, err := s.Resolve("app")
// res.Selected / res.Closure / res.Excluded / res.SecurityRevision

// 影响查询：某版本的生效隔离记录与沿依赖图被波及的版本
report, err := s.Impact(pv.ID)

// 审计与修订号
entries := s.AuditLog()
rev := s.SecurityRevision()
```

## 错误分类

所有业务错误均为 `*packagequarantine.Error`，可用 `KindOf(err)` 提取类别：

| 类别 | 含义 |
| --- | --- |
| `ErrKindParam` | 参数错误：缺请求号、版本号格式非法、依赖重复声明等 |
| `ErrKindDependency` | 依赖错误：依赖不存在、依赖成环、依赖被隔离波及 |
| `ErrKindDigest` | 摘要错误：摘要格式非法，或同名同版本摘要不一致 |
| `ErrKindIdempotency` | 幂等冲突：同一请求号携带了不同内容 |
| `ErrKindNotFound` | 目标版本 / 隔离单不存在 |
| `ErrKindState` | 状态错误：如重复解除同一隔离单 |

## 运行测试

    go test -race ./...

测试覆盖：发布校验（参数 / 摘要 / 依赖缺失 / 自环）、不可变性、幂等重放与冲突、
隔离沿依赖图传播与解释路径、多条隔离的解除语义、安全修订号快照、影响查询、
持久化恢复，以及发布 / 隔离 / 解析并发下“迟到发布不能绕开已确认隔离”的不变量。
