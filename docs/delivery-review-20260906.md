# Dependency Delivery Review

## Scope And Design

保留 `6bb34545b4f89f1f6c265a68c18f1a40ade413eb` 上十二项既有修改，
包括 bounded producer catch-up、异步发布准备、piggyback 验证与诊断。
修复 `unsubscribe()` 的生命周期缺口：订阅注册表和 fetch 队列中的副本
共享活性标志；Face 所属的取消操作先撤销该标志，所有交付路径先检查它。
此标志不承诺跨线程修改订阅容器安全，也不取消其他订阅者共享的 fetch。
新增回归要求真实 catch-up 响应继续交付给保留订阅者，但不调用已取消订阅。

Catch-up 数量上限适用于全部匹配 producer session 的总和，保持现有实现。
随后普通合并 `origin/Experimental`，保留远端协议修复和本机功能，禁止强推。

## Validation And Checkpoint

- [x] Local changes: static review, focused regression and complete unit suite.
- [x] Remote integration: normal merge, static review and complete unit suite.
- [x] Delivery: exact commit, ABI/source identity and isolated source/build pair.

独立构建目录和原始日志位于 `.codex-tmp/svs-delivery-20260906-r1/`；
不覆盖既有 `build/`，不修改全局安装。系统 GCC 9.4、binutils 2.34、
Boost 1.71 与 ndn-cxx 0.9.0 已完成路径核验。

Context Mode 项目文档索引/检索与 CodeGraph 检索通过。跨库 Spec Kit
指向 Spec182；旧 AGENTS 示例中的 Spec003 更新命令不覆盖当前主任务上下文。
GSD health 无 errors，存在四项旧 worktree warning；未删除这些工作区。

### Local Review R1

隔离 configure/build PASS（build 63.437s）。首次定向命令遗漏
`TestSVSPubSub/` suite 前缀，框架在 test selection 阶段 exit200，未运行回归；
见 `unsubscribe-red-r1/output.log`。`test-list-r1` 已核对真实测试层级，
下一次使用完整 suite/case 路径，不能将选例错误当作代码失败。

`unsubscribe-red-r2` 真实执行回归：保留订阅得到 Data，同时已取消订阅的
计数为 1，违反期望 0，exit201。共享活性标志修复后重建并复验。

`build-green-r1` PASS（18.167s）；`unit-local-r1` 完整运行 **80/80 cases、
590/590 assertions PASS**（6.491s），含新的取消回归和已有晚到回调、
验证失败、恢复/分段、异步提交测试。`git diff --check` PASS。
这是当前本机源的库级测试，不等于合并远端之后或 NDNSF/SIF 的资格证据。

### Remote Merge Design

本机 checkpoint `3f50301` 后普通合并远端 `b3e3814`。两边历史各有九项
独立提交；以原本机 `6bb3454` 的内容为对照，逐文件保留远端协议变化与
本机修改，避免 add/add 冲突覆盖已测工作。保留本机更完整的 core 并行回归。

远端为 MappingProvider/MappingList 增加 V2/V3 参数，但 PubSub 调用点仍
默认 V3。保持默认 V3，仅贯通已有显式 `options.syncProtocol.version`：
构造 MappingProvider、piggyback 编码/重置及收到 Mapping 的预验证/解码。
新增真实 PubSub V2 Mapping 编码/接收及 query/响应回归，不能只测试独立 codec。

`build-merge-red-r1` PASS（30.335s）。`v2-mapping-red-r1` 两个真实用例均
FAIL：显式 V2 发出 V3 Mapping，且 query 含 V3 bootstrap 位置/typed seq；
原始证据保留，参数贯通后重建复验。fixture README 同步已合并的 signed
extension 格式，保留独立编码器及其输入字节。

### Merged Verification

`build-merge-green-r1` PASS（18.149s）；`unit-merged-r1` 完整运行
**87/87 cases、639/639 assertions PASS**（6.528s），含两个 V2 PubSub 回归、
catch-up 取消、原有串行/并行 core 与远端 signed extension 负例。
最终源以包含本记录的普通 merge commit 固定，父节点保留本机 checkpoint
和远端 `b3e3814df135b3cda1bd69c605e145fb3468f204`；不重写远端历史。

Source/build pair 为本仓库与 `.codex-tmp/svs-delivery-20260906-r1/build/`。
`runtime-identity.json` 确認单测加载该目录的 SVS、系统 Boost 1.71 和
`/usr/local/lib/libndn-cxx.so.0.9.0`；SVS SHA-256 为
`a9944819a86557882108badf7b04fa698ebc067a17e95031c535adb50d723424`。
旧 `build/` 和全局安装未修改。

ABI 不能沿用旧对象：Fetcher/SVSPubSub 的新增字段、Options、Subscription
共享活性状态、MappingList/MappingProvider 的协议状态均须由同版头文件消费。
SONAME 仍为 `0.1.0`，其不变不构成兼容证明；NDNSF/Core/Python 应从干净
对象重新构建。本文库级通过不替代新消费者、SIF 或实验资格验收。
