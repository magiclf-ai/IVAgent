本 testcase 已切换到 `Input Engine = ida` 契约。

此目录应存放可由 IDA 打开的权威资产，例如 `.i64`、`.idb` 或与之配套的离线伪代码快照。

当前仓库尚未补齐真实 IDA 资产。为了维持 `tests/eval` 回归链路，runner 会在缺失真实资产时退回 `authoring/source` 或 `source` 生成合成伪代码输入。
