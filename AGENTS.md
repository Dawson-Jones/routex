# AGENTS.md — routex

本文件补充 `~/.claude/CLAUDE.md` 中的通用原则, 仅记录本项目在演进过程中确立的、不能从代码直接读出的规则.

## 协议层验证: Reference 不是 Ground Truth

涉及 syscall / netlink / route socket / ioctl 等 in-band 协议时, 参考实现 (如 `reference/darwin_route/route.c`) 反映的是 "那个程序往内核发了什么", 不是 "内核拿这些字段做什么". 二者经常不一致.

**规则**: 当行为依据来自参考实现的源码时, 必须用 black-box 行为测试验证 kernel 实际匹配/响应 key, 然后再写代码. 不要把 "reference 这么写" 当成 "kernel 这么用".

**Why**: macOS RTM_DELETE 实证, kernel 只用 `RTA_DST + RTA_NETMASK` 匹配, 而 darwin route CLI 在 `NEXTADDR` 序列里把 caller 提供的 `RTA_GATEWAY` / `RTA_IFP` 也写进 message. 一度据此误推 "delete 应当带 gateway/ifindex 作为约束", 后续实验证伪. 验证方法:
```
sudo route add 1.2.3.4/32 10.0.0.1
sudo route delete 1.2.3.4/32 10.0.0.2  # 错的 gateway 也能命中 → kernel 不看 gateway
sudo route delete -ifp lo0 1.2.3.4/32  # 错的 ifp 也能命中 → kernel 不看 ifp
```

**How to apply**:
1. 写 add/delete/get 之类 path 前, 先用 CLI 跑"错配 selector"的反例, 确认哪些字段是 kernel 真正的 match key.
2. 代码里只写 kernel 用到的 selector, 不要为了"和 reference 对齐"塞额外字段.
3. 在容易回归的位置 (例如 `write_route_addrs` 这种构造 rtm_addrs 的函数) 留一行注释, 说明字段取舍的实证依据, 防止下次又被 reference 源码带偏.

## 平台抽象边界

`src/lib.rs` 是平台无关层 (`Route`, `RouteAction` trait, `Route::validate`), `src/linux/` 和 `src/macos/` 是各自的 wire-format 实现. 跨平台共用的 helper (例如地址族转换、prefix → mask) 放在 `lib.rs`; 协议特定的 helper (`route_message`, `write_route_addrs`, `read_route` 等) 留在各自模块.

**Why**: Linux netlink 和 macOS route socket 在 wire format / 字段语义 / 错误模型上都不同, 强行抽象成统一 trait 之外的"通用 helper" 会引入边界不清的双胞胎实现. 当前划分让两个 OS 模块的内部演进互不影响.

**How to apply**: 看到两边出现"形似但语义不同"的代码, 默认不抽象; 只有当语义真的等价 (例如 `IpAddr` ↔ `AddressFamily` 这种纯转换) 才上提到 `lib.rs`.

## 内核响应解析的 sequence number

Linux netlink 当前 `nl_hdr.sequence_number = 1` 硬编码, 没有响应 seq 校验. 已在三处 add/delete/get 标注 TODO. 单线程同步 send-recv 场景下没问题, 一旦 socket 被多线程共用或与 monitor 流复用就会读到串台消息.

**How to apply**: 在 `RouteSock` 结构上加 `AtomicU32` 维护单调递增 seq, 发送前 `fetch_add`, parse 响应时校验 `nlmsg.header.sequence_number == expected`, 不匹配的丢弃并继续读. 改完后把三处 TODO 注释一并移除.
