#  ACE 反作弊能力范围分析报告

**分析对象**：（`xxxx.exe`）随附的 ACE（Anti-Cheat Expert）反作弊套件
**分析路径**：`E:\code\ai\xxxx\game\\AntiCheatExpert\`
**分析日期**：2026-10-19
**分析工具**：REA MCP（Ghidra 12.1.4 无头分析后端）+ 全量 PE 字符串普查
**报告性质**：**防御性 / 合规视角的能力清单**，用于理解该反作弊系统的作用范围与数据采集面。不包含任何绕过或对抗手段。

---

## 0. 执行摘要

这套 ACE 不是一个单一客户端插件，而是**用户态 + 内核态双层、常驻服务 + 注入式 DLL + 内核驱动 + 云端策略下发**的完整反作弊体系。共 **27 个自研组件**（x86/x64 各一套），签名主体为海外实体 **ACEVILLE PTE LTD**（新加坡）。

从能力边界看，ACE 的重心**不在客户端"抓现行"，而在"高权限取证 + 特征库比对 + 服务端裁决"**：

| 层级 | 关键能力 |
|---|---|
| **内核态**（Ring 0） | 跨进程内存读写、物理内存映射、句柄表枚举、进程/线程全量遍历 |
| **用户态（游戏进程内）** | 代码段/IAT 完整性校验、全量内存扫描、内联钩子引擎、DX API 定位 |
| **用户态（服务进程）** | Macode 病毒库 + 外挂特征库扫描、取证任务编排、崩溃现场转储 |
| **云端** | 策略远程下发、特征库云更新、检测结果裁决与处罚下发 |

**最值得注意的是 3 点**：

1. **内核驱动具备无限制的进程内存读写能力**（`KeStackAttachProcess` + `\Device\PhysicalMemory`），用户态检测无法覆盖的行为，内核层可回溯取证。
2. **集成了 AI 视觉检测**（ACE-CSI64 内嵌 OpenCV 4.5.5 + YOLO 目标检测），具备对画面内容做目标识别的能力（如 Overlay/绘制外挂识别）。
3. **处罚由服务端下发并本地强制执行**（`punish_type` / `punish_duration` / `punish_reason`），客户端只是执行器 —— 这意味着检测判定权不在本地。

**同时明确发现的空白**（对评估"ACE 能做什么/不做什么"同样重要）：无 SSDT Hook、无文件系统微过滤驱动、无内核回调注册、无调试器名黑名单、**几乎无虚拟机/沙箱检测**、**无自瞄/宏等输入级检测**。这类检测主要交给服务端行为分析，不在客户端组件内。

---

## 1. 方法论与可信度声明

| 手段 | 覆盖 | 说明 |
|---|---|---|
| **REA / Ghidra 12.1.4 反编译分析** | 5 个组件 | ACE-Helper.exe、ACE-Safe.dll、ACE-SSC-DRV64.sys、ACE-SSC64.dll、AceXGame.dll；ACE-CSI64.dll 因 12MB 超分析时限失败 |
| **全量 PE 字符串普查** | 27 个组件（708,548 行 / 10.2 MB） | ASCII(≥5) + UTF-16LE(≥4) 双路提取；用于建立能力面全景 |
| **PE 结构/节名分析** | 全部 | 识别加固壳、CFG、Detours 标记 |

**证据分级**（报告中逐条标注）：

- **【实测】** — 由 REA/Ghidra 直接观测，附 SHA-256 与地址
- **【字符串直证】** — 二进制中明文字符串直接命中，附原文
- **【推断】** — 由 API 组合、PE 结构、PDB 路径等合理还原，已标注
- **【未发现】** — 精确检索后确认不存在（**注意：不等于运行时不存在** —— 见第 6 节局限性）

**样本 SHA-256（REA 权威计算）**

| 组件 | SHA-256 |
|---|---|
| ACE-Helper.exe | `0c11249157e3a97e5aba91ab3de233d9eb94ecf47dbf8d26e5010bd6261c5f08` |
| AceXGame.dll | `8f7e704424392f9a8cfe4a94d33fe7fa6dae137b718a97e132dbf4c7d1f629b1` |
| ACE-Safe.dll (x86) | `707797aaaa5f50487ce8d49ada36473d8f1737ab656ccafae637af4095042f2b` |
| ACE-SSC64.dll | `259dd0035bf0de4efd8b0effb982b2b61c6aa7155fc7225479bae59a7c026823` |
| ACE-SSC-DRV64.sys | `d2c2403aa0d67b99e7a49be6998021c867d8729a044022f59aa855ffdfc6ec4e` |
| ACE-CSI64.dll | `4fcb76334f4c3e6f3b93cc848bfbabeb6da7e38c3469780706cc01fef3ecc84a` |

---

## 2. 组件清单与职责

### 2.1 InGame 层（随游戏分发，注入游戏进程）

| 组件 | 版本 | 职责 | 证据 |
|---|---|---|---|
| **ACE-Base32.dll** | 1.0.2310.730 | **客户端 API 入口层**，游戏唯一直接对接模块 | 导出 `InitAceClient` / `InitAceClient0..4`【字符串直证】 |
| **ACE-Safe.dll** | 6.2.2308.1133 | **主检测引擎**，承载 AntiBot +  TSS/TenProtect SDK | 命名空间 `AntiBot`(22类) / `tss_anti_sdk`(13类)【实测】 |
| **ACE-ATS32/64.dll** | 2.0.2404.517 | **代码防篡改系统**（Anti-Tamper System） | `CCodeAntiTamper`、`CMemDiscoverWorker`、`CMemPunishWorker`【字符串直证】 |
| **ACE-CSI32/64.dll** | 4.0.2310.157 | **客户端安全巡检** + **AI 视觉检测** | 内嵌 OpenCV 4.5.5-dev + `YoloDetectionOutput`【字符串直证】 |
| **ACE-DFS32/64.dll** | 1.3.2402.491 | **策略探针**（Policy Probe）—— 执行云端下发的检测策略 | PDB `PolicyProbex86s.pdb`【字符串直证】 |
| **ACE-DRV32/64.dll** | 1.0.2405.13265 | **Detours 内联钩子引擎**（体量最大：15.9/18.8 MB） | PE 节名 `.detourc` / `.detourd`【字符串直证】 |
| **ACE-Trace.dll** | 7.6.2212.89 | **崩溃/异常现场采集与上报** | `MiniDumpWriteDump`、`%SystemRoot%\Minidump`【字符串直证】 |
| **ACE-Tips32.dll** | 1.0.2208.114 | **提示 UI 渲染 + DX 函数定位器** | PDB `ACEDXFuncFinder32.pdb`、`CreateDXGIFactory1`【字符串直证】 |
| **tersafe32.dll** | 6.2.2211.1045 | **TerSafe 传统端游反作弊**（ACE 前身，兼容期共存） | `FileDescription=TerSafe`、`tessafe.sys`【字符串直证】 |
| **TCJ.dll** | 4.0.2111.51 | **早期 ACE-CSI 分支**（行为日志 + 计时采样） | `tensp::CBehaviorLog`、`tensp::CTickTime`【字符串直证】 |
| **SGuardAgent32.dll** | 1.0.2308.22 | 游戏进程 ↔ SGuard 服务的 **IPC 客户端** | `CIpcClient@IPC@TGuard`【字符串直证】 |

### 2.2 SGuard 层（安装到 `%ProgramFiles%\AntiCheatExpert\`，常驻）

| 组件 | 版本 | 职责 | 权限 |
|---|---|---|---|
| **SGuardSvc32/64.exe** | 1.0.2402.35 | **Windows 服务**（显示名 `AntiCheatExpert Service`） | **SYSTEM** |
| **SGuard32/64.exe** | 1.0.2402.35 | **常驻守卫客户端**：IPC 服务端、上报、处罚下发 | 用户 |
| **SGuardUpdate32/64.exe** | 1.0.2402.35 | **自动更新器**（提权链入口） | 提权 |
| **ACE-SSC32/64.dll** | 0.1.2404.398 | **扫描 + 取证 + 风险评级核心** | SYSTEM |
| **ACE-SSC-DRV64.sys** | 0.1.2404.398 | **内核驱动** | Ring 0 |
| **Uninstall32/64.exe** | 1.0.2209.13 | 卸载器 | 提权 |

### 2.3 缩写释义

| 缩写 | 释义 | 证据强度 |
|---|---|---|
| **ATS** | **A**nti-**T**amper **S**ystem 代码防篡改系统 | 字符串直证（`CCodeAntiTamper`） |
| **CSI** | **C**lient **S**ecurity **I**nspection 客户端安全巡检 | 版本资源直证，全拼为推断 |
| **DFS** | **Policy Probe** 策略探针 | PDB 直接证明 |
| **SSC** | **S**can & **S**ecurity **C**ore 扫描取证内核 | RTTI 直证（`CSscImpl`、`SSCForensics`） |
| **DRV** | 驱动侧客户端，内嵌 Microsoft Detours | PE 节名直证 |
| **TSS** | TenProtect 安全外壳 SDK | `tss_anti_sdk` 命名空间 + GUID |
| **SGuard** | 内部项目名 **ACE-Guard** | PDB 路径 `CommonComponent\ACE-Guard\` |

---

## 3. 能力范围详解

### 3.1 代码防篡改（ACE-ATS）—— 最高强度

ACE 对**游戏客户端自身的完整性**做了多层校验，这是反作弊的地基：

```
FileMemIATChecker@CodeAntiTamper     ← IAT 导入表：磁盘文件 vs 内存比对
FileMemCmpChecker@CodeAntiTamper     ← 代码段逐字节比对
MemoryChecker / MemoryCheckerEx      ← 内存页校验
ModuleBasicInfo@CodeAntiTamper       ← 模块基线快照
CMemDiscoverWorker                   ← 内存篡改发现
CMemPunishWorker                     ← 篡改处罚执行器
CMonoATSHashWorker                   ← 通用哈希校验
CMonoATSSpecificHashWorker           ← 特定哈希校验
CMonoATSHookWorker                   ← Hook 型校验
get_tampered_methods                 ← 枚举被篡改的方法
```
*来源*：`CodeAntiTamperInfrastructure\ModuleMemMgr\MemReader.cpp` 源码路径残留【字符串直证】

### 3.2 内存检测

| 能力 | 实现 |
|---|---|
| **全量内存扫描** | `CRpFullMemScan` / `IRpFullMemScan`（ACE-Safe / tersafe） |
| **快速扫描** | `CRpFastScanImp` / `IRpFastScan` |
| **远程内存扫描** | `CRemoteMemDiscoverWorker`（跨进程） |
| **线程 Pin（防调试/防挂起）** | `CRcPinImp`、`CDnfRcPinImp` |
| **内存区域枚举**（SSC 独有完整集） | `MEM_COMMIT`/`MEM_FREE`/`MEM_IMAGE`/`MEM_MAPPED`/`MEM_PRIVATE` + `PAGE_EXECUTE*` 全套 + `+PAGE_GUARD`/`+PAGE_NOCACHE`/`+PAGE_WRITECOMBINE` |
| **跨进程读写** | `WriteProcessMemory`、`VirtualAllocEx`、`VirtualProtectEx`、`SetProcessWorkingSetSize` |

### 3.3 进程 / 线程 / 模块

- **全量枚举**：`CreateToolhelp32Snapshot` + `Process32First/Next` + `Thread32First/Next` + `Module32First/Next`
- **远程线程注入**（多模块具备）：`CreateRemoteThread` / `CreateRemoteThreadEx`
- **线程挂起/恢复**：`SuspendThread` / `ResumeThread`
- **完整路径**：`QueryFullProcessImageNameW`、`K32GetProcessImageFileNameW`
- **权限提升**：`SeDebugPrivilege`、`SeTcbPrivilege`、`SeProfileSingleProcessPrivilege`、`SeBackupPrivilege`

### 3.4 内核驱动（ACE-SSC-DRV64.sys）—— 能力上限所在

这是整个套件中权限最高、覆盖最全的组件：

```
【跨进程内存访问】
  KeStackAttachProcess / KeUnstackDetachProcess     ← 挂载到任意进程地址空间
  ZwQueryVirtualMemory / ZwQueryInformationProcess
  ZwQueryInformationThread / ZwQuerySystemInformation
  PsGetProcessImageFileName / SeLocateProcessImageName
  MmCopyMemory / MmMapIoSpace

【直接物理内存】
  \Device\PhysicalMemory                             ← 绕过进程隔离的物理内存访问

【进程/线程遍历】
  PsLookupProcessByProcessId / PsLookupThreadByThreadId
  PsGetThreadProcess / PsGetThreadProcessId
  PsGetProcessExitStatus / PsGetProcessExitProcessCalled
  ExEnumHandleTable / ObFindHandleForObject          ← 句柄表枚举

【反静态分析】
  MmGetSystemRoutineAddress + ntoskrnl.exe           ← 动态解析内核 API
  ZwQuerySymbolicLinkObject                          ← 探测符号链接
  KeRegisterBugCheckReasonCallback / KeBugCheckEx    ← 蓝屏回调

【硬件拓扑感知】
  KeQueryActiveProcessors / KeQueryActiveProcessorCountEx
  KeGetProcessorNumberFromIndex / KeQueryMaximumProcessorCount
  KeSetSystemGroupAffinityThread / KeRevertToUserGroupAffinityThread
  HalDispatchTable                                   ← HAL 分发表访问
```
*证据*：REA/Ghidra 直接观测【实测】，sha256 `d2c2403a…`

**设备与符号链接**：`\Device\ACE-SSC-DRV64`、`\DosDevices\ACE-SSC-DRV64`
**服务键**：`\Registry\Machine\System\CurrentControlSet\Services\ACE-SSC-DRV64`

> **要点**：内核驱动可读取**任意进程**内存与句柄表。这意味着用户态检测不到的隐藏行为，只要进程还在，内核层原则上都能回溯取证。

### 3.5 钩子与注入

| 技术 | 证据 |
|---|---|
| **内联钩子引擎** | ACE-DRV 内嵌 Microsoft Detours（PE 节 `.detourc`/`.detourd`） |
| **主动 inline hook** | `add_inline_hook`（ACE-Base） |
| **消息钩子** | `SetWindowsHookExW` / `CallNextHookEx` / `UnhookWindowsHookEx`（ACE-CSI64、ACE-Helper） |
| **DX API 定位** | `D3D11CreateDeviceAndSwapChain`、`CreateDXGIFactory1`、`@ACEDXFuncFinder` —— 用于定位游戏渲染调用点 |
| **多入口加载** | ACE-Safe 存在 `DllEntry0` ~ `DllEntry8` 共 9 个 DllMain 入口【实测】 |

### 3.6 文件扫描与外挂特征库（ACE-SSC）—— 判定外挂的主要抓手

ACE-SSC **复用了电脑管家（Macode）的病毒扫描引擎**，并扩展了游戏专属威胁类型：

**威胁类型枚举**【rea/Ghidra 实测，ACE-SSC64.dll】：

| 枚举值 | 含义 |
|---|---|
| `Unknown_VirusType` | 未知 |
| `Trojan` | 木马 |
| `Infect` | 感染型 |
| `Downloader` | 下载器 |
| `Cheat` | **外挂** |
| `GoldFarming` | **刷金/刷农场** |
| `GameAssistant` | **游戏辅助/外挂工具** |
| `NetBar` | 网吧类工具 |

**风险评级**：`White` / `Grey` / `Black` / `Unknown_Risk`
**其他枚举**：`Unknown_Platform`/`Win32`/`Win64`、`Unknown_Entry`/`HeaderEntry`/`PEEntry`
**特征库**：`config\TenMacode.dat`
**策略配置目录**：`r/ssc_ptn_cfg/`

**取证子系统**（RTTI 直证）：
```
CSscImpl::(SSC_EXTRA_SCAN_OBJECT_INFO_W)      ← 扫描对象描述结构
SSCForensics::CTaskInfo                       ← 取证任务
CWorkerManager::Priority                      ← 任务优先级队列
Forensics::_APPCOMPAT_ERROR
```
**扫描目标模式**：`App.exe`、`%s\*.*`、`NTFS`、`\\.\%C:`、`%C:\`
**白名单目标**：`msedge`、`WXWork`（企业微信）、`WeChat`

### 3.7 AI 视觉检测（ACE-CSI64）—— 值得单独关注

ACE-CSI64 **静态链接了完整的 OpenCV 4.5.5-dev**，并包含 YOLO 目标检测实现：

```
OpenCV 4.5.5-dev              （cv::imdecode / cv::imencode / cv::resize / cv::dnn）
YoloDetectionOutput
Yolov3DetectionOutput
DetectionOutput
```
*来源*：ACE-CSI64.dll 字符串【字符串直证】

**能力推断**：具备对游戏画面做目标检测以识别 Overlay / 绘制类外挂的能力。
**注意**：ACE-CSI64 自身未出现截图 API（`BitBlt`/`PrintWindow`），图像来源应为游戏渲染回读或其他模块协作 —— **此环节为推断，非直接证据**。

补充：ACE-Helper.exe 具备完整 GDI 屏幕捕获链（`GetWindowDC` → `CreateCompatibleDC` → `CreateDIBSection` → `BitBlt` → `StretchBlt`）【实测】。

### 3.8 反调试与时间源校验

| 能力 | 覆盖 |
|---|---|
| `IsDebuggerPresent` | **全部 13+ 个组件** |
| `NtQueryInformationProcess` | Base、CSI、SGuard 全家、TCJ |
| 异常流程劫持 | `SetUnhandledExceptionFilter` / `UnhandledExceptionFilter`（全部） |
| **多时间源交叉校验** | `rdtsc`（ATS/Base/CSI/TCJ）+ `QueryPerformanceCounter`/`Frequency`（全部）+ `timeGetTime`（DRV/Tips）+ `GetTickCount64` + `GetSystemTimeAsFileTime` |
| 崩溃转储 | `MiniDumpWriteDump` + `dbghelp.dll`（CSI、Trace、SGuard） |

**判定**：**变速/加速器检测能力成立** —— ACE 同时掌握三种独立计时源，可交叉比对检测时间加速。

**重要否定**：`OllyDbg`/`x64dbg`/`WinDbg`/`Immunity`/`SoftICE` 等**调试器名黑名单完全未发现**【未发现】。ACE 不靠"进程名黑名单"抓调试器。

### 3.9 设备指纹采集

| 维度 | API |
|---|---|
| CPU 特征 | `cpuid`（ATS/Base/CSI/SGuardUpdate/TCJ） |
| 网卡 / MAC | `GetAdaptersAddresses`、`GetAdaptersInfo`、`Net Bios Description`、`CMACReaderEx@MACReader3GEx` |
| 磁盘卷序列号 | `GetVolumeInformationA` / `GetVolumeInformationW` |
| GUID | `CoCreateGuid`、`UuidCreate`、`UuidFromStringA` |
| 显卡 / 显示器 | `EnumDisplayDevicesA`（Trace）、`CreateDXGIFactory1`（Tips） |
| 磁盘容量 | `GetDiskFreeSpaceExA` |
| 系统版本 | `VerifyVersionInfoA` |
| 域 / 网络环境 | `WLDAP32.dll`、`NETAPI32.dll`、`iphlpapi.dll` |
| 硬件加密服务 | `Intel Hardware Cryptographic Service Provider` |

**不查 WMI / SMBIOS**（`Win32_Processor`/`Win32_BIOS`/`SMBIOS` 全部未发现），硬件指纹走原生 API。

### 3.10 网络通信与数据上报

**硬编码端点**：

| 端点 | 用途 |
|---|---|
| `down.anticheatexpert.com` | 软件更新服务器 |
| `down.safe.wegame` | WeGame 平台安全下载 |
| `anticheatexpert.com` | 公司主域（签名/校验） |
| IPv4 | **DNSPod HTTP-DNS**，抗运营商 DNS 劫持 |
| 80 个中国电信/联通骨干 IP | 游戏主控服务器兜底直连 |

**URL 模板**：
```
http://%s/d?dn=%s                HTTP-DNS 解析
http://%s/d?dn=%s&id=%s          HTTP-DNS 解析（带校验）
https://%s/cgi-bin/susup/upload   现场/样本上传
https://%s/cgi-bin/susup/infocheck 环境自检上报
```

**通信协议栈**（自研，tersafe32 原文）：
```
[SECCLI:TCP] service-id and event-handler has registered[%u]...
recv pkg piece:%u|%u          ← 分片传输
data hole [%u/%u][%u]         ← 空洞重组
crc check error!              ← CRC 校验
ResetSendDataEncrpy Crc Fail! ← 发送数据加密
Get Skey Success! / Get VerifyValue Success!
invalid session! / invalid uin! / invalid game id!
recv queue timeout: 90s / send queue timeout: 30min
```
叠加： **TDR** 序列化库（`TdrBuf.h`）+ **Rijndael** 加密（`CRijndael@tcj_encrypt`）
静态内嵌 **libcurl + OpenSSL 0.9.8zg**（ACE-Base/Trace）

**账号/环境上报字段**：
```
TssAccountInfo { account_id_.account_:%s, account_type_:%d, plat_id_:%d,
                 game_id_:%d, world_id_:%d, channel_id_:%d, role_id_:%d }
```

### 3.11 策略远程下发（ACE-DFS / DataProxy）

ACE 具备**服务端驱动检测策略**的能力：

```
AntiBot::IDataProxy / CDataProxyImp / IDPClientSink    ← 数据代理（下发通道）
AntiBot::TPChannelAdapter                               ← 通道适配
AntiBot::ISolutionEvent                                ← 方案事件
tss_anti_sdk::ITssDP / CTssDPImp / TssDPObject         ← DP 通道
AntiBot::IAntiBot3 / IAntiBot4                         ← 两代检测引擎并存
tss_anti_sdk::IAntiClient / IAntiClientEx              ← 客户端 SDK 接口
```

**更新任务 JSON schema**（SGuardUpdate 直证）：
```
protocol_version, product_version, file_list, restart, async,
os_version, cpuid, mac_list, update, gameid, ingame, bin_ver
```
→ **更新包选择逻辑会参考本机 CPU 与 MAC 列表**，说明更新是差异化定向的。

**版本协商**：`cutVer from net-msg not in [BASEVERSION, CURRVERSION]`
**本地库**：内嵌 **SQLite 3.9.2**（`CREATE TABLE IF NOT EXISTS KV(...)`）+ `sldh.dat`
**任务线程池**：`tensp::CTaskCenter`、`CTaskStatusTracker`、`CWorkerManager`、`CUploadDumpTask`、`CCollectFileTask`、`CBehaviorLog`、`CTickTime`

### 3.12 处罚机制（服务端裁决 + 客户端执行）

```
[ACE-Base schema 定义]
{"punish_type": "%s\n(%d-%d-%d) ", "punish_duration": "%s", "punish_reason": ""}
punish_type / punish_duration / punish_reason / GetPrivateTips

[SGuard32/64 实际执行]
punish_type、punish_duration、punish_reason
```

**要点**：
1. 处罚**由服务端下发**（`cmd_id` / `body_len` 命令信封），本地只执行；
2. 处罚含**类型**（`punish_type`）、**时长**（`punish_duration`）、**理由**（`punish_reason`）三要素；
3. 存在日期区间格式 `(%d-%d-%d)`，暗示存在**周期性/累犯封禁**机制；
4. `GetPrivateTips` 表明处罚文案可由服务端定制。

### 3.13 自保护

| 机制 | 证据 |
|---|---|
| **内存篡改处罚执行** | `CMemPunishWorker`（ACE-ATS） |
| **完整性自检** | `integrity_check` / `IntegrityCk`（SGuard 全家） |
| **代码签名校验** | `WinVerifyTrust`、`wintrust.dll`、`crypt32.dll` |
| **共享对象宽松 SDDL** | `D:(A;;GA;;;WD)(A;;GA;;;AN)S:(ML;;;;;S-1-16-0)` —— Everyone/Anonymous 全权 + **低完整性级别标记**（`S-1-16-0` = Low Mandatory Level），专门防提权绕过 |
| **自保护加载** | `DllEntry0..DllEntry8` 多入口 |
| **自身加固** | 多数组件带 `@.tvm0`（ VM）/ `@.vmp0`（VMProtect）节 + CFG（`.gfids`） |

### 3.14 自更新链路

```
SGuardUpdate64.exe  ─(runas 提权)─→  SGuard64.exe  ─→  SGuardSvc64.exe
                                                              │
        下载(down.anticheatexpert.com) ← 服务端下发 file_list  │
        停服务 → 覆盖文件 → 装服务 → 启动服务 → 启动 SGuard   │
```
状态机原文（完整）：
```
download start. / download failed. / download complete. / download all success.
try stop sguard success. / try stop sguard failed.
service exist. / service path. / install service failed. / install service success.
start service failed. / start service success.
start sguard failed. / start sguard success.
set security failed. / copy result / backup result / update complete.
```

### 3.15 安装与卸载

**安装**：安装 `SGuardSvc` 为 **Windows 自动启动服务**（SYSTEM 权限）+ `ACE-SSC-DRV64` 内核驱动服务。
**卸载**：`ACE-Uninstall.exe` 执行 4 步 —— 停/删服务 → 递归删注册表 → 删文件（system32/ProgramData/ProgramFiles）→ 自复制到 `%TEMP%` 设重启删除后回删。

**卸载器源码结构（直接暴露工程组织）**：
```
src\main.cpp / files.cpp / registry.cpp / services.cpp / compatiblity.cpp
```
**驱动清理是枚举式的**（非硬编码服务名）：遍历 `HKLM\SYSTEM\CurrentControlSet\Services`，读取 `Start`/`Type`/`ImagePath`，匹配 `\drivers\` + `.sys` + `system32`。

> **重要发现**：**未发现任何卸载保护机制**【未发现】。未找到卸载校验、卸载密码、回调拦截或"禁止卸载"逻辑。卸载流程线性可自动执行。

---

## 4. 能力边界（明确未发现的能力）

以下是精确检索后**确认不存在**于客户端组件的能力，理解这些边界与理解已有能力同样重要：

| 能力 | 检索结论 |
|---|---|
| **SSDT Hook** | 未发现 `SSDT` / `KeServiceDescriptorTable` |
| **内核回调注册** | 未发现 `ObRegisterCallbacks` / `CmRegisterCallback` / `PsSetCreateProcessNotifyRoutine` |
| **文件系统微过滤驱动** | 未发现 `FltRegisterFilter` / `minifilter` / `ReadDirectoryChangesW` |
| **调试器名黑名单** | 未发现 OllyDbg / x64dbg / WinDbg / Immunity / SoftICE |
| **硬件断点检测** | 未发现 DR0-DR7 相关检测 |
| **虚拟机 / 沙箱检测** | **仅 1 个孤立字符串 `vmware`**（4 处命中），无 VBox/Hyper-V/QEMU/Sandboxie |
| **自瞄 / 宏 / 输入模拟检测** | 所有命中均可归因于 MFC GUI 或 OpenSSL ASN.1，**实质证据为零** |
| **WMI / SMBIOS 硬件查询** | 未发现 `Win32_*` WMI 类名 |
| **杀软进程名黑名单** | 未发现 |
| **抓包工具检测** | 未发现 Fiddler / Wireshark 特征 |

> **解读**：自瞄/宏/变速的**行为判定主要在服务端**（依赖玩家行为时序统计），客户端只负责采集原始信号与特征库比对。这与 ACE "高权限取证 + 云端裁决" 的架构一致。

---

## 5. 安全与隐私影响评估

| 维度 | 评估 | 依据 |
|---|---|---|
| **系统侵入性** | **高** | 内核驱动常驻 + SYSTEM 服务 + 驱动可读物理内存 |
| **数据采集广度** | **高** | CPU/MAC/磁盘卷序列号/网卡/显示器/域环境/内存布局 |
| **通信加密** | **已加密** | 自研 TCP + 分片/CRC/加密 + TDR + Rijndael + OpenSSL；HTTP-DNS 抗劫持 |
| **远程控制能力** | **高** | 策略下发、特征库更新、版本裁剪、处罚下发、模块热更 |
| **可审计性** | **低** | VM/VMProtect 加固 + 字符串加密 + PDB 剥离；客户端不可审计 |
| **卸载可行性** | **可行** | 未见卸载保护，但需管理员权限且游戏运行时受限 |
| **隐私透明度** | **低** | 全部客户端组件字符串均为英文，**未发现任何中文隐私说明或数据用途告知**；隐私政策需另行查证 |

---

## 6. 局限性与未决问题

**必须声明的分析局限**（避免过度解读本报告）：

1. **静态字符串 ≠ 运行时行为**。 VM（`.tvm0/.tvm51/.vmp0`）保护的模块在静态下只暴露加载器壳。AceXGame.dll 经 REA 分析仅 53 个可见函数、120 个字符串（对比 ACE-Helper 的 13,166 函数），**真实逻辑在运行时解密**。所有"未发现"结论均受此限制约束。
2. **分析不完全**。ACE-CSI64.dll（12MB）超出 Ghidra 分析时限未能反编译验证，其 AI 视觉检测能力仅由字符串证据支撑。ACE-DRV32/64（15.9/18.8MB）几乎完全剥离。
3. **仅静态分析**，未做任何运行时观测（无动态 Hook、无流量捕获、无沙箱执行）。
4. **提取管线限制**。字符串普查管道丢弃了非 ASCII 字符，因此**报告中"无中文文案"是提取缺陷，不是 ACE 的实际情况** —— 中文处罚/提示文案极可能以 UTF-16 存在于 `.rsrc` 或运行时解密区。
5. **单一版本快照**。各模块版本跨度很大（ACE-Trace 7.6 / ACE-Safe 6.2 / ACE-ATS 2.0 / ACE-SSC 0.1），说明部分模块长期未更新或采用不同版本策略。
6. **云 AKID 暴露**。ACE-Safe.dll 中发现硬编码的云访问密钥 ID `AKIDMXXKyOOUAalna7OQCm9MMMDrFNFroUQ6` 及配套会话密钥字符串。这是**厂商侧的信息卫生问题**（客户端硬编码密钥必然可提取），但该 AKID 本身不构成安全漏洞。

**建议的后续调查方向**（如需深化）：

- 对 `AceXGame.dll` / `ACE-DRV64.dll` 做运行时脱壳后再分析（动态 dump），这是当前最大盲区
- 抓取 ACE 运行时网络流量，确认 `[SECCLI:TCP]` 协议的实际字段与上报内容
- 分析 `config\TenMacode.dat` 与 `r/ssc_ptn_cfg/` 策略包，量化外挂特征库覆盖范围
- 从 `ACE-SSC-DRV64.sys` 的 IOCTL 分发例程入手，枚举驱动提供的完整命令集

---

## 7. 附录：架构图

```
┌───────────────── 游戏进程 (xxxx.exe / dnf.exe / crossfire.exe) ─────────────────┐
│ <游戏目录>\AntiCheatExpert\InGame\{x86|x64}\                                  │
│                                                                              │
│  ACE-Base32.dll  ← 游戏唯一 API 入口 (InitAceClient*)                        │
│    ├── ACE-Safe.dll ........ 主检测引擎 (AntiBot / tss_anti_sdk)               │
│    │                           ├── CRpFullMemScan   全量内存扫描              │
│    │                           ├── CRcPinImp        线程 Pin                  │
│    │                           └── 内嵌 TCJUpload / tscNet / OpenSSL            │
│    ├── ACE-ATS32/64.dll ..... 代码防篡改 (IAT/代码段比对 + 处罚)              │
│    ├── ACE-CSI32/64.dll ..... 安全巡检 + OpenCV/YOLO 视觉检测                │
│    ├── ACE-DFS32/64.dll ..... 策略探针 (PolicyProbe) 执行云端策略             │
│    ├── ACE-Trace.dll ........ 崩溃现场 MiniDump 采集上报                     │
│    ├── ACE-Tips32.dll ....... 提示 UI + DX 函数定位器                        │
│    ├── SGuardAgent32.dll ..... IPC 客户端                                     │
│    ├── ACE-DRV32/64.dll ...... Detours 内联钩子引擎                          │
│    └── tersafe32.dll ......... TerSafe 传统反作弊（兼容共存）                 │
└──────────────────────────┬───────────────────────────────────────────────────┘
                           │ 共享内存 TCLS_SHAREDMEMEMORY / tsid sharemem / SMEM
                           ▼
┌─────────── Windows 服务 (SYSTEM, 自动启动) ──────────────────────────────────┐
│ %ProgramFiles%\AntiCheatExpert\SGuard\{x86|x64}\                            │
│   SGuardSvc32/64.exe   "AntiCheatExpert Service"                            │
│     ├── 内嵌 SQLite (KV 表) + sldh.dat                                      │
│     ├── ACE-SSC64.dll ──► \\.\ACE-SSC-DRV64 ──► ACE-SSC-DRV64.sys (Ring 0)   │
│     │                       · KeStackAttachProcess   跨进程内存读写          │
│     │                       · \Device\PhysicalMemory 物理内存                │
│     │                       · ExEnumHandleTable      句柄枚举                │
│     ├── Macode 特征库扫描 (Cheat / GameAssistant / GoldFarming / Trojan...) │
│     └── SSCForensics 取证任务编排 (CWorkerManager::Priority)               │
└──────────────────────────┬───────────────────────────────────────────────────┘
                           │ TCP [SECCLI:TCP] 分片 + CRC + 加密 + TDR
                           │ Skey / VerifyValue / uin / gameid 认证
                           │ cmd_id / body_len  命令与处罚下发
                           ▼
     游戏服务器 (80 个硬编码 IP)        HTTP: down.anticheatexpert.com (更新)
                                      HTTP-DNS: 119.29.29.29
                                      HTTPS: /cgi-bin/susup/{upload,infocheck}
```

---

## 8. 能力速查表

| # | 能力 | 强度 | 主要承载组件 |
|---|---|---|---|
| 1 | 代码段 / IAT 完整性校验 | ★★★★★ | ACE-ATS |
| 2 | 内核跨进程内存读写 | ★★★★★ | ACE-SSC-DRV64.sys |
| 3 | 外挂特征库扫描（Macode） | ★★★★★ | ACE-SSC64 |
| 4 | 全量内存扫描 | ★★★★☆ | ACE-Safe / tersafe |
| 5 | 内联钩子（Detours） | ★★★★☆ | ACE-DRV |
| 6 | 策略远程下发 / 云端裁决 | ★★★★☆ | ACE-DFS / DataProxy |
| 7 | 变速检测（多时间源交叉） | ★★★★☆ | ATS / Base / CSI / DRV |
| 8 | 设备指纹采集 | ★★★★☆ | 全部 |
| 9 | 反注入 / 线程枚举 | ★★★☆☆ | Base / CSI / SSC |
| 10 | AI 视觉检测（YOLO） | ★★★☆☆ | ACE-CSI64 |
| 11 | 崩溃现场采集上报 | ★★★☆☆ | ACE-Trace |
| 12 | 代码签名校验 | ★★★☆☆ | Base / WinVerifyTrust |
| 13 | 自更新（定向差异化） | ★★★☆☆ | SGuardUpdate |
| 14 | 反调试（通用 API） | ★★☆☆☆ | 全部 |
| 15 | 虚拟机 / 沙箱检测 | ★☆☆☆☆ | 仅 1 处 `vmware` 字符串 |
| 16 | 自瞄 / 宏 / 输入检测 | ☆☆☆☆☆ | 客户端无（交服务端） |

---

*报告结束。所有结论均基于对上述 27 个静态二进制的分析，未执行任何被分析程序，未产生任何绕过建议。*