# 在新 Kali 部署 RL78 兼容版 REA

这是**部署管理员**指南，不是正式受试 agent 的输入或分析提示。本目录只含通用软件、版本锁和配置工具，不包含真实目标、目标指纹、函数清单、语义答案或开发期证据。

## 下载哪个仓库、哪个分支

新机只需公开源码仓库 **`Taiyixcx/rea` 的 `experiment/rl78` 分支**：

```sh
git clone --branch experiment/rl78 --single-branch https://github.com/Taiyixcx/rea.git rea-rl78
cd rea-rl78
REA_SOURCE_COMMIT=$(git rev-parse HEAD)
git switch --detach "$REA_SOURCE_COMMIT"
```

记录实际下载的完整提交；本次部署后固定在该提交，不在正式运行期间 pull 或换版本。默认 main 是另一条上游版本线，不是本兼容部署入口。

**不要下载私有 `rea-compat` 来作为受试工作区，也不要搬运整个研发目录。** 私有准备库、其 Git 历史、旧数据库、报告、证据、研发对话与记忆都属于管理员资料。即使删除当前文件，Git 历史仍可能保留它们；不同目录也不等于权限隔离。

## 部署之前

本流程支持 Linux x86-64。固定软件版本见 [software-pins.json](software-pins.json)：IDA 9.5、Node 24.18.0、npm 11.16.0、Python 3.13.16、官方 ida-mcp 20261008.0.1；其余 Python 依赖见 [requirements-ida.txt](requirements-ida.txt)。

先检查已有软件。缺失的必要版本仅在本部署目录建立独立运行环境，不替换系统默认解释器或安装无关引擎。IDA 安装、可用许可及 idalib 由操作者提供；不要读取、打印或复制许可密钥内容。没有必要条件时，报告缺项，不冒称成功。

当前配置工具不安装软件、不激活许可、不修改 Codex 配置，也不证明新机已验收。它检查版本和已构建软件核心，生成当前机器的候选配置。

## 安装官方 MCP 与 Python 绑定

在新机重新建立虚拟环境，不复制旧机器的 venv。以下命令中的路径均需替换为本机绝对路径：

```sh
python3.13 -m venv /absolute/ida-env
/absolute/ida-env/bin/python -m pip install /absolute/ida-9.5/idalib/python/idapro-0.0.10-py3-none-any.whl
/absolute/ida-env/bin/python /absolute/ida-9.5/idalib/python/py-activate-idalib.py -d /absolute/ida-9.5
/absolute/ida-env/bin/python -m pip install -r deployment/requirements-ida.txt
/absolute/ida-env/bin/python -m pip check
```

激活脚本会设置该用户的 IDA 绑定路径；已有设置应先备份。`idapro` 使用所安装 IDA 随附的 wheel。固定依赖，不使用会自动跟随最新版的默认 uvx 配置。官方 MCP 的 headless 路线不要求 GUI 插件；本配置强制 idalib 工作模式。

官方依据：[IDA MCP](https://github.com/HexRaysSA/ida-mcp)、[IDA Domain 绑定说明](https://ida-domain.docs.hex-rays.com/faq/)。

## 构建与打包

确保所选 Node/npm 在当前 PATH 中，并先核对版本：

```sh
node --version
npm --version
npm ci
cat node_modules/turbo/docs/README.md
npm run build:cached
git status --short
```

上游 AGENTS.md 对安装的 Turbo 文档有要求；按其中对应运行任务说明执行，不改 Turbo 配置。可选第三方引擎子模块不是本 IDA 路线的前置条件。

不要执行 `npm install rea-agents@6.7.0` 作为获取补丁的方法，它取得的是原版。要传递安装包时，从本固定源码构建：

```sh
mkdir -p /absolute/admin-output/software
npm pack --pack-destination /absolute/admin-output/software
python3 deployment/check-package.py /absolute/admin-output/software/rea-agents-6.7.0.tgz
```

审计器按软件白名单拒绝数据库、S-record、许可证及研发目录，并检查整个已锁定的运行核心摘要。它不证明主机隔离有效，也不能替代源代码审阅。只传软件包和版本锁；不要把数据库、日志或证据一起打包。

## 生成本机配置

输出目录必须在源码工作区之外，并属于部署管理员：

```sh
python3 deployment/configure.py \
  --node /absolute/node-24/bin/node \
  --npm /absolute/npm-11/bin/npm \
  --python /absolute/ida-env/bin/python \
  --ida-dir /absolute/ida-9.5 \
  --output /absolute/admin-output/host \
  --check

# 上一步通过后，去掉 --check，再执行同一命令生成文件
```

会生成：

| 文件                | 用途                                                        |
| ------------------- | ----------------------------------------------------------- |
| `ida-official.json` | REA 到官方 MCP 的内部配置，含本机绝对路径与私有状态目录     |
| `codex-a1.toml`     | REA 组的 Codex MCP 注册提案                                 |
| `codex-a0.toml`     | 原生组的官方 MCP 注册提案                                   |
| `rea-skill/`        | 与软件核心匹配的通用 REA 技能和参考文件                     |
| `host.json`         | 本机软件身份及 `configured-not-verified` 状态；不是资格证书 |
| `validation/`       | 本机通用样本报告目录；管理员保管，不给受试 agent            |

在生成时会检查源码干净、固定版本和运行核心摘要。重复执行同一配置无变化；已有不完整或不同配置时拒绝覆盖。不要改预期摘要来消除错误。

应用客户端配置前备份当前配置；保留其他无关设置和凭据，不打印凭据。只合入用户选择角色对应的那一段，不能把两个角色都暴露给同一受试 agent。Codex 的 MCP 注册支持 command/args/env；见[官方 MCP 配置](https://developers.openai.com/codex/mcp)。配置后重连并用 `binary_session` 核对软件路径与实际提交。技能安装也须属于对应实验工作区，不覆盖其他组的全局技能。

## 新机验收只用通用样本

部署阶段不打开真实实验固件，不遍历它的函数，也不检索相关答案。配置好必要路径后，在管理员会话运行：

```sh
export REA_IDA_MCP_CONFIG=/absolute/admin-output/host/ida-official.json
export REA_BUILD_COMMIT=$(git rev-parse HEAD)
npm run verify:ida -- --fixture --target-format s-record --architecture rl78 \
  --pseudocode-expectation unavailable --all-functions \
  --report /absolute/admin-output/host/validation/fixture.json
npm run verify:ida:recovery -- --report /absolute/admin-output/host/validation/recovery.json
```

需要持续运行验证时，对同一通用 fixture 增加 `--duration-seconds 7200`，报告写入独立文件。这些是软件/通用样本验证，不可写成新机真实目标验收结果。内核必须实际报告 IDA 9.5；不支持的反编译器按 unavailable 验收，仍须验证汇编、身份、分页、恢复、导出和关闭。失败如实保留，禁止用本机之外的历史报告填补。

实际验收后记录该机配置、软件/依赖哈希和报告，封存并只读使用。这里没有可直接搬用的原开发机 qualified 清单；本机生成配置也不会自动升级为“已验收”。源码 checkout 用于部署/构建，正式角色仅访问允许的软件接口、匹配技能及当次资料；不要把整个 Git 工作区和管理员输出挂给受试 agent。

## 正式实验边界

- 部署 Codex 和受试 Codex 必须是不同的新会话。不要将部署会话分叉、摘要、记忆或历史检索连接传给受试会话。
- 原生组只暴露官方 IDA MCP；REA 组只暴露 REA MCP。底层 CPU、加载、IDA/MCP 版本、输入资料保持一致。没有适用的 RL78 反编译器时，两组都按事实记录；不替某一组偷偷补充伪代码。
- 只切 MCP 注册不构成强隔离。如果仍能读管理员目录、读取其他组文件或用 shell 直接启动被禁止的后端，隔离仍未通过。使用适当的独立账号、容器/服务端权限和工具白名单，并实测禁止访问是否真的失败。
- 正式运行从三份允许输入、新数据库和新账本开始；真实目标的首次加载和分析按实验协议计时。软件安装与通用样本验收在准备阶段完成。
- 本目录不提供评分答案，也不宣称输出校验、日志、硬停止或四组整体流程已经配置完毕。

## 可交给部署 Codex 的请求

```text
这条会话仅用于部署管理，不用于正式受试分析。
请阅读本仓库 AGENTS.md 和 deployment/README.md，部署 experiment/rl78 的兼容版。
先发现并核对现有 IDA、Node/npm、Python 路径；缺少合法 IDA/idalib 条件时询问我，不猜测、不复制许可。
按固定版本建立独立环境、构建并审计软件包，运行 configure.py 生成本机配置。
我授权你在备份后只修改所选实验角色所需的 Codex MCP/技能配置，保留其他配置；尚未指定角色时先询问。
仅使用仓库生成的通用样本做验收，不读取真实实验固件、旧库、研发档案或历史分析会话。
报告实际通过、失败和未验证项；不要照搬别台机器的 qualified 标记。
结束后给出本机提交、软件身份、启动配置及尚未完成的隔离/正式实验准备项。
```
