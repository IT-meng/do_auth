# do_auth.py 脚本逻辑详细分析

## 1. 概述

`do_auth.py` 是一个用 Python 编写的 TACACS+ 授权脚本，作为 `tac_plus` TACACS+ 守护进程的后授权（after authorization）脚本使用。它提供了比 `tac_plus` 原生配置更灵活的认证和授权控制能力，允许基于**用户来源IP**、**目标设备IP**、**用户名**和**命令**进行细粒度的访问控制。

**作者**: Dan Schmidt, Jathan McCollum  
**版本**: 1.13  
**许可证**: GPL-3.0

---

## 2. 整体架构

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────────┐
│ tac_plus    │────>│ do_auth.py   │────>│ do_auth.ini  │────>│ 匹配判定      │
│ (TACACS+    │     │ (授权脚本)    │     │ (配置文件)    │     │ 允许/拒绝     │
│  守护进程)   │     │              │     │              │     │ exit(0)/exit(1)│
└─────────────┘     └──────────────┘     └──────────────┘     └───────────────┘
       │                    │
       │  传入参数:          │  读取 stdin:
       │  -u $user          │  AV pairs
       │  -i $address       │
       │  -d $name          │
       │  -f config_file    │
       │  -l log_file       │
       └────────────────────┘
```

脚本通过命令行参数接收用户名、来源IP、设备IP等信息，通过 stdin 接收 TACACS+ AV pairs，然后根据配置文件中的规则进行匹配判定，最终通过**退出码**返回授权结果：
- **exit(0)**: 授权允许
- **exit(1)**: 授权拒绝
- **exit(2)**: 授权允许，但需要替换 AV pairs（`AUTHOR_STATUS_PASS_REPL`）

---

## 3. 模块导入与全局变量

### 3.1 兼容性导入

```python
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
```

兼容 Python 2/3 的 `configparser` 模块导入。Python 2 中模块名为 `ConfigParser`，Python 3 中为 `configparser`。

### 3.2 NSS 组查询（可选）

```python
try:
    from os import getgrouplist as os_getgrouplist
    from pwd import getpwnam as pwd_getpwnam
    from grp import getgrgid as grp_getgrgid
    got_getgrouplist = True
except ImportError:
    got_getgrouplist = False
```

尝试导入 OS 级别的用户组查询函数（仅 Linux 支持 `os.getgrouplist`），用于将用户所属的 NSS（Name Service Switch）组自动映射为 do_auth 的授权组。

### 3.3 全局常量

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `CONFIG` | `'do_auth.ini'` | 默认配置文件路径 |
| `LOG_FILE` | `'/dev/null'` | 默认日志文件路径 |
| `LOG_LEVEL` | `logging.INFO` | 默认日志级别 |
| `LOG_FORMAT` | 时间戳 + 级别 + 消息 | 日志格式 |
| `DEBUG` | `os.getenv('DEBUG', False)` | 环境变量控制调试模式 |
| `SKIP_CONVERT` | `['user-permissions']` | AV pair 替换时跳过的属性名（Juniper 特殊处理） |

### 3.4 `_product` 函数（兼容性）

```python
try:
    from itertools import product
except ImportError:
    product = _product
```

`itertools.product` 在 Python 2.6 才引入，脚本自带了一个 `_product` 实现以兼容 Python 2.3+。该函数计算笛卡尔积，用于参数顺序检查。

---

## 4. 核心函数分析

### 4.1 `_setup_logging(filename, format, level)`

**功能**: 初始化并返回全局日志对象。

**逻辑**:
1. 调用 `logging.basicConfig()` 配置日志级别、格式和输出文件
2. 返回 `logging.getLogger(__name__)` 日志对象

**注意**: 此函数在 `main()` 中被调用，返回值赋给全局变量 `log`。

### 4.2 `dprint(*args, **kwargs)`

**功能**: 调试打印函数，仅在 `DEBUG` 环境变量设置时输出。

**逻辑**:
- 遍历位置参数，逐个 `print`
- 遍历关键字参数，以 `KEY = value` 格式输出

### 4.3 `get_attribute(config, the_section, the_option, filename)`

**功能**: 从配置文件中获取指定 section 和 option 的值，返回为列表（按行分割）。

**逻辑**:
1. 检查 section 是否存在，不存在则 `sys.exit(1)`
2. 检查 option 是否存在，不存在则 `sys.exit(1)`
3. 调用 `config.get()` 获取原始字符串值
4. 用 `splitlines()` 按行分割为列表
5. 过滤空行，返回非空行列表

**异常处理**: 捕获了 `NoSectionError`、`DuplicateSectionError`、`NoOptionError`、`ParsingError` 四种异常，均以 `sys.exit(1)` 退出。

**返回值示例**: 如果配置中某个选项值为多行：
```ini
host_allow =
    1.1.1.*
    2.2.2.*
```
则返回 `['1.1.1.*', '2.2.2.*']`

### 4.4 `check_username(config, user_name)`

**功能**: 检查用户名是否存在于配置文件的 `[users]` section 中。

**逻辑**:
1. 检查 `[users]` section 是否存在，不存在则 `sys.exit(1)`
2. 返回 `config.has_option('users', user_name)` 的布尔值

**与 `get_attribute` 的区别**: 此函数不会因用户不存在而退出，仅返回 `True/False`，允许回退到默认配置。

### 4.5 `match_it(the_section, the_option, match_item, config, filename)`

**功能**: 判断 `match_item` 是否匹配配置中指定 section/option 下的任一正则表达式。

**逻辑**:
1. 检查 option 是否存在，不存在则返回 `False`（隐式拒绝）
2. 获取该 option 的所有值（正则表达式列表）
3. 逐个用 `re.match()` 匹配 `match_item`
4. 任一匹配成功返回 `True`，全部不匹配返回 `False`

**关键点**: 使用的是 `re.match()` 而非 `re.search()`，即正则从字符串开头匹配。因此配置中的 `.*` 可以匹配任意字符串，`10.1.1.*` 匹配以 `10.1.1.` 开头的所有IP。

### 4.6 `DoAuthOptionParser` 类

**继承自**: `optparse.OptionParser`

**功能**: 自定义命令行解析器，重写 `error()` 方法：
- 遇到选项错误时始终以退出码 `1` 退出（而非默认的 `2`）
- 将错误信息写入日志文件
- 如果全局 `log` 对象尚未初始化，则先初始化日志

**设计原因**: `tac_plus` 根据退出码判断授权结果，退出码 `2` 可能被误解读，因此统一为 `1`（拒绝）。

### 4.7 `is_i_before_f(argv, parser)`

**功能**: 确保 `-i` 参数在 `-f` 参数之前。这是 Cisco CRS（IOS-XR）的 bug 变通方案。

**逻辑**:
1. 获取 `-f` 和 `-i` 选项的所有短名和长名
2. 计算笛卡尔积，检查所有组合
3. 如果 `-f` 和 `-i` 都存在，且 `-f` 在 `-i` 之前，则报错

**原因**: IOS-XR 的 `$address` 变量可能包含 `-fix_crs_bug` 后缀，如果 `-f` 在 `-i` 之前，该后缀会被误解析为 `-f` 的参数值。

### 4.8 `parse_args(argv=None)`

**功能**: 解析命令行参数。

**支持的参数**:

| 参数 | 说明 | 必需 |
|------|------|------|
| `-u / --username` | 用户名（对应 `$user`） | **是** |
| `-i / --ip-addr` | 用户来源IP（对应 `$address`） | 否 |
| `-d / --device` | 目标设备IP（对应 `$name`） | 否 |
| `-f / --config-file` | 配置文件路径（默认 `do_auth.ini`） | 否 |
| `-l / --log-file` | 日志文件路径（默认 `/dev/null`） | 否 |
| `--docs` | 显示文档并退出 | 否 |
| `-D / --debug` | 调试模式 | 否 |

**特殊逻辑**:
- 如果未提供 `-u`，报错退出
- 调用 `is_i_before_f()` 检查参数顺序
- **IOS-XR 兼容**: 如果 `config_file` 被解析为 `ix_crs_bug`（即 `-fix_crs_bug` 被误当作 `-f` 的参数），则将其修正为 `ip_addr` 的值，并恢复 `config_file` 为默认值

---

## 5. `main()` 函数核心流程

### 5.1 流程总览

```
┌──────────────────────┐
│ 1. 解析命令行参数      │
├──────────────────────┤
│ 2. 初始化日志          │
├──────────────────────┤
│ 3. 读取 stdin AV pairs │
├──────────────────────┤
│ 4. 解析 AV pairs       │
│    - 提取命令          │
│    - 提取返回 pairs    │
├──────────────────────┤
│ 5. 读取配置文件        │
├──────────────────────┤
│ 6. 查找用户所属组      │
├──────────────────────┤
│ 7. 遍历组进行匹配判定  │
│    - host_deny/allow  │
│    - device_deny/permit│
│    - av_pairs 替换    │
│    - exit_val 处理    │
│    - command_deny/permit│
├──────────────────────┤
│ 8. 隐式拒绝（兜底）    │
└──────────────────────┘
```

### 5.2 步骤详解

#### 步骤 1-2: 参数解析与日志初始化

```python
opts, _args = parse_args()
log = _setup_logging(filename=log_name)
```

#### 步骤 3: 读取 AV pairs

从 stdin 逐行读取 AV pairs。在调试模式下，使用默认的模拟命令：
```
service=shell
cmd=show
cmd-arg=users
cmd-arg=wide
cmd-arg=<cr>
```

如果没有收到任何 AV pairs，脚本认为配置有误（可能是 `tac_plus.conf` 缺少 `default service = permit`），直接 `sys.exit(1)`。

#### 步骤 4: 解析 AV pairs

这是脚本中最复杂的部分，根据 AV pairs 的内容区分三种场景：

**场景 A: Cisco Nexus 登录**
```
service=shell
cmd=          ← 空的 cmd= 表示 Nexus 登录
shell:roles="network-operator"  ← Nexus 特有的 AV pair
...
```
- 检测条件: `av_pairs[0] == "service=shell\n"` 且 `av_pairs[1] == "cmd=\n"`
- 处理: 跳过前两个 pair，将后续 pairs 作为 `return_pairs`

**场景 B: 命令授权**
```
service=shell
cmd=show
cmd-arg=users
cmd-arg=wide
cmd-arg=<cr>
```
- 检测条件: `av_pairs[1]` 以 `"cmd="` 开头
- 处理: 将 `cmd=` 和所有 `cmd-arg=` 拼接为完整命令字符串 `the_command`
  - 例如: `"show users wide"`
  - 遇到 `<cr>` 表示命令结束
  - 防火墙设备不发送 `<cr>`，因此用数组越界作为退出条件
  - 跳过只包含换行符的空行

**场景 C: 登录授权（非 Nexus）**
```
service=shell
cmd*           ← 注意是 cmd* 而非 cmd=
priv-lvl=1
shell:roles="network-operator"
```
- 检测条件: `av_pairs[1]` 以 `"cmd*"` 开头（`*` 表示可选值）
- 处理: 跳过 `cmd*` pair，将后续 pairs 作为 `return_pairs`
- **额外处理**: 如果 `return_pairs` 中包含 `shell:roles`（Nexus 特有），则移除它（因为这不是 Nexus 设备）

**场景 D: 非 shell 服务**
- 检测条件: `av_pairs[0]` 不是 `"service=shell\n"`
- 处理: 直接将所有 AV pairs 作为 `return_pairs`

#### 步骤 5: 读取配置文件

```python
config = configparser.SafeConfigParser()
config.readfp(open(filename))
```

使用 `SafeConfigParser`（Python 2 兼容写法）读取 INI 配置文件。

#### 步骤 6: 查找用户所属组

```python
if not check_username(config, user_name):
    user_name = user_name + ":(default)"
    groups = get_attribute(config, "users", "default", filename)
else:
    groups = get_attribute(config, "users", user_name, filename)
```

**逻辑**:
1. 如果用户名在 `[users]` section 中不存在，查找 `default` 键
2. 用户名后追加 `:(default)` 标记（用于日志区分）
3. 如果用户存在，直接获取其所属组列表

**NSS 组扩展**:
```python
if '_nss' in groups and got_getgrouplist:
    pwd_user = pwd_getpwnam(user_name)
    os_group = os_getgrouplist(user_name, pwd_user[3])
    for gid in os_group:
        group = grp_getgrgid(gid)
        groups.append(group[0])
```
- 如果组列表中包含特殊标记 `_nss`，且系统支持 `getgrouplist`
- 则查询操作系统的 NSS（Name Service Switch）获取用户的所有系统组
- 将系统组名追加到 do_auth 的组列表中

#### 步骤 7: 遍历组进行匹配判定

这是授权的核心逻辑，按顺序遍历用户所属的每个组：

```
对于每个组 this_group:
    ├── 检查 host_deny（来源IP拒绝）
    ├── 检查 host_allow（来源IP允许）
    ├── 检查 device_deny（设备IP拒绝）
    ├── 检查 device_permit（设备IP允许）
    ├── 处理 av_pairs 替换
    ├── 处理 exit_val
    ├── 如果是登录（无命令）→ 返回 AV pairs 并退出
    └── 如果是命令授权 → 检查 command_deny / command_permit
```

**7a. host_deny 检查**
- 仅在提供了 `-i` 参数时执行
- 如果来源IP匹配 `host_deny` 中的任一正则：
  - 如果是最后一个组 → `sys.exit(1)`（拒绝）
  - 否则 → `continue`（跳到下一个组）

**7b. host_allow 检查**
- 如果来源IP不匹配 `host_allow` 中的任何正则：
  - 特殊情况: 如果 `ip_addr == "-fix_crs_bug"`（IOS-XR bug 变通），跳过此检查
  - 如果是最后一个组 → `sys.exit(1)`（拒绝）
  - 否则 → `continue`

**7c. device_deny 检查**
- 仅在提供了 `-d` 参数时执行
- 逻辑同 host_deny

**7d. device_permit 检查**
- 逻辑同 host_allow（无 `-fix_crs_bug` 特殊处理）

**7e. AV pairs 替换**

这是高级功能，用于修改返回给设备的 AV pairs：

**替换模式 1: 逗号分隔（属性名替换）**
```ini
av_pairs =
    priv-lvl,brocade-privlvl=5
```
- 含义: 将 `priv-lvl=XX` 替换为 `brocade-privlvl=5`
- 用途: Brocade 设备需要 `brocade-privlvl` 而非标准 `priv-lvl`
- 逻辑: 将 AV pair 按 `=` 分割为 `attr` 和 `value`，如果 `av_pairs` 配置项中包含逗号，且逗号前的属性名与当前 AV pair 的属性名匹配，则替换为逗号后的内容

**替换模式 2: 等号分隔（属性值替换）**
```ini
av_pairs =
    priv-lvl=15
    shell:roles="network-admin"
```
- 含义: 将 `priv-lvl=XX` 替换为 `priv-lvl=15`
- 逻辑: 如果属性名匹配，则整个替换为配置中的新值

**特殊处理**:
- `SKIP_CONVERT` 列表中的属性（如 `user-permissions`）不进行逗号分隔的替换，因为 Juniper 的 `user-permissions` 值本身可能包含逗号
- 替换发生后设置 `want_tac_pairs = True`，影响最终退出码

**7f. exit_val 处理**

```python
exit_val = '2'  # 默认值
if config.has_option(this_group, "exit_val"):
    return_val = get_attribute(config, this_group, "exit_val", filename)
    return_val = return_val[0]
    exit_val = return_val.strip()
```

- 默认退出码为 `2`（`AUTHOR_STATUS_PASS_REPL`），表示需要替换 AV pairs
- HP Procurve 设备不支持 `AUTHOR_STATUS_PASS_REPL`，需设置为 `0`
- 仅取第一个值（多个值无意义）

**7g. 登录授权（无命令时）**

如果 `the_command` 为空（登录阶段）：
1. 打印 `return_pairs` 到 stdout（这是返回 AV pairs 给 `tac_plus` 的方式）
2. 记录授权日志
3. 以 `exit_val` 退出

**7h. 非 shell 服务授权**

如果 AV pairs 的 service 不是 `shell`：
1. 直接打印 `return_pairs`（截取 `av_pairs[2:]`）
2. 如果 `want_tac_pairs` 为 True，以 `exit_val` 退出
3. 否则以 `0` 退出（不修改 AV pairs）

**7i. 命令授权**

如果 `the_command` 非空（命令授权阶段）：
1. 检查 `command_deny`: 命令匹配则拒绝
2. 检查 `command_permit`: 命令匹配则允许（`sys.exit(0)`）
3. 都不匹配: 如果是最后一个组则拒绝，否则继续下一个组

#### 步骤 8: 隐式拒绝

如果遍历完所有组都没有匹配，执行隐式拒绝：
```python
sys.exit(1)
```

---

## 6. 配置文件格式

### 6.1 `[users]` section

```ini
[users]
homer =
    simpson_group
    television_group
stimpy =
    television_group
default =
    readonly_group
```

- 每个用户对应一个或多个组，每行一个
- `default` 是特殊的回退键，当用户名不存在时使用

### 6.2 组定义 section

```ini
[simpson_group]
host_deny =
    1.1.1.1
    1.1.1.2
host_allow =
    1.1.1.*
device_permit =
    10.1.1.*
command_permit =
    .*

[television_group]
host_allow =
    .*
device_permit =
    .*
command_permit =
    show.*
```

### 6.3 组选项说明

| 选项 | 必需 | 说明 |
|------|------|------|
| `host_deny` | 否 | 拒绝来自这些来源IP的用户（正则匹配） |
| `host_allow` | 是（如指定了 `-i`） | 允许来自这些来源IP的用户（正则匹配） |
| `device_deny` | 否 | 拒绝访问这些设备IP（正则匹配） |
| `device_permit` | 是（如指定了 `-d`） | 允许访问这些设备IP（正则匹配） |
| `command_deny` | 否 | 拒绝这些命令（正则匹配） |
| `command_permit` | 是 | 允许这些命令（正则匹配） |
| `av_pairs` | 否 | AV pair 替换规则 |
| `exit_val` | 否 | 硬编码退出码（默认为 `2`） |

---

## 7. 匹配顺序与优先级

### 7.1 组的顺序

组的处理顺序**严格遵循用户定义中的顺序**，从上到下。这是关键设计：

```
用户 homer 的组: [simpson_group, television_group]
```

- 先检查 `simpson_group`，如果全部通过则授权成功
- 如果 `simpson_group` 中有 deny 或不匹配，**继续**检查 `television_group`
- 一个组授予的权限**不能**被后续组撤销

### 7.2 组内选项的检查顺序

```
host_deny → host_allow → device_deny → device_permit → av_pairs → exit_val → command 检查
```

- `deny` 优先于 `allow`/`permit`
- 命令检查仅在登录阶段之后执行

### 7.3 隐式拒绝

如果所有组都不匹配，最终结果是**拒绝**（`sys.exit(1)`）。

---

## 8. 设备特殊处理

### 8.1 Cisco Nexus

**问题**: Nexus 设备在登录时发送空的 `cmd=` AV pair，并使用 `shell:roles` 属性。

**处理**:
- 检测到 `cmd=\n` 时，识别为 Nexus 登录
- 保留 `shell:roles` AV pair 以传递给 Nexus
- 非 Nexus 设备登录时（`cmd*`），自动移除 `shell:roles`

### 8.2 Brocade

**问题**: Brocade 使用 `brocade-privlvl` 而非标准 `priv-lvl`。

**处理**:
- 使用 `av_pairs` 的逗号分隔语法进行属性名替换:
```ini
av_pairs =
    priv-lvl,brocade-privlvl=5
```

### 8.3 HP Procurve

**问题**: Procurve 不支持 `AUTHOR_STATUS_PASS_REPL`（退出码 2）。

**处理**:
- 设置 `exit_val = 0`
- 必须将 Procurve 组放在**最前面**

### 8.4 Cisco IOS-XR (CRS)

**问题**: IOS-XR 在 `$address` 变量后附加 `-fix_crs_bug` 字符串。

**处理**:
- 命令行参数 `-i` 必须在 `-f` 之前
- 脚本检测到 `-fix_crs_bug` 后自动修正参数解析
- 在 `host_allow` 检查中，如果 `ip_addr == "-fix_crs_bug"`，跳过检查

---

## 9. 退出码含义

| 退出码 | TACACS+ 含义 | do_auth 使用场景 |
|--------|-------------|-----------------|
| `0` | `AUTHOR_STATUS_PASS_ADD` | 命令授权通过 / 不需要修改 AV pairs |
| `1` | `AUTHOR_STATUS_FAIL` | 授权拒绝 |
| `2` | `AUTHOR_STATUS_PASS_REPL` | 登录授权通过，需要替换 AV pairs（默认） |

---

## 10. 典型 tac_plus 配置

```bash
after authorization "/usr/bin/python /root/do_auth.pyc -i $address -fix_crs_bug -u $user -d $name -l /root/log.txt -f /root/do_auth.ini"
```

参数说明：
- `$address`: 用户来源IP（tac_plus 内置变量）
- `$user`: 用户名
- `$name`: 设备名称/IP
- `-fix_crs_bug`: IOS-XR bug 变通参数
- `-l`: 日志文件
- `-f`: 配置文件

---

## 11. 已知问题与注意事项

1. **正则表达式错误**: 如果配置了无效的正则（如 `*.` 而非 `.*`），Python `re` 模块会抛出异常
2. **组顺序至关重要**: 宽泛的组（如 `.*` 匹配所有设备）必须放在最后，否则会"吞掉"所有匹配
3. **一个组不能撤销另一个组的权限**: 授权是累加的，deny 只在当前组内生效
4. **AV pair 替换是 find/replace 语义**: 只有匹配到的属性才会被替换，未匹配的保持不变
5. **stdin 读取是阻塞的**: 在非调试模式下，脚本会等待 stdin 输入
6. **`optparse` 已弃用**: Python 3 中推荐使用 `argparse`，但脚本为兼容旧版 Python 仍使用 `optparse`
7. **`SafeConfigParser` 已弃用**: Python 3.2+ 推荐使用 `ConfigParser`
8. **`config.readfp()` 已弃用**: Python 3.2+ 推荐使用 `config.read_file()`

---

## 12. 安全考量

1. **隐式拒绝**: 默认拒绝所有未明确允许的访问
2. **deny 优先于 permit**: 在同一组内，deny 检查先于 permit
3. **日志记录**: 所有授权决策都有日志记录
4. **配置文件权限**: 配置文件应设置适当的文件权限，防止未授权修改
5. **正则注入**: 配置文件中的正则表达式如果被恶意修改，可能导致非预期的授权结果