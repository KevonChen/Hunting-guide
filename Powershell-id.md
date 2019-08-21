说明：岁数大了，记忆力不好。做数据分析的时候经常用到powershell相关知识，特做此记录。

# Powershell

## Powershell各版本对比

PowerShell是一种功能强大的脚本语言和shell程序框架，主要用于Windows计算机方便管理员进行系统管理并有可能在未来取代Windows上的默认命令提示符。PowerShell脚本因其良好的功能特性常用于正常的系统管理和安全配置工作，然而，这些特性被攻击者理解并转化为攻击特性，也成为了攻击者手中的利器，给企业网络造成威胁。

### PowerShell V2

PowerShell V2提供事件记录能力，可以协助蓝队进行相关的攻击事件推断和关联性分析，但是其日志记录单一，相关Post-Exploitation可做到无痕迹；并且因为系统兼容性，在后续版本攻击者都会尝试降级至此版本去躲避日志记录。

### PowerShell V3/V4

PowerShell V3/V4 相比之前提供了更全面的日志记录功能。Windows PowerShell 3.0 改进了对命令和模块的日志记录和跟踪支持。 自PowerShell v3版本以后支持启用PowerShell模块日志记录功能，并将此类日志归属到了4103事件。PowerShell模块日志可以配置为记录所有的PowerShell模块的活动情况，包括单一的PowerShell命令、导入的模块、远程管理等。可以通过GPO进行启用模块日志记录。

### PowerShell V5

PowerShell V5加入了CLM和ScriptBlock日志记录功能，能去混淆PowerShell代码并记录到事件日志。随着PowerShell攻击技术的不断成熟，攻击者为了规避防护和日志记录进行了大量的代码混淆，在执行代码之前很难发现或确认这些代码实际上会做些什么事情，给攻击检测和取证造成了一定的困难，因此微软从PowerShell5.0开始加入了日志转储、ScriptBlock日志记录功能，并将其归入到事件4104当中，ScriptBlock Logging提供了在事件日志中记录反混淆的 PowerShell 代码的能力。

### PowerShell V6

PowerShell V6 出于功能需求，提供了更全面的系统覆盖能力。由于PowerShell在Linux和MacOS等操作系统上的支持在MacOS上安装（pwsh），处于安全性考虑日志记录作为必不可少的一部分，PowerShell使用本机os_log API登录Apple的统一日志记录系统。在Linux上，PowerShell使用Syslog，微软将此上升成为一种几乎全平台支持的日志记录解决方案。

### PowerShell  V7

PowerShell  V7（PS7）基于.NET Core 3.0，Microsoft旨在提供与Windows PowerShell模块更高的兼容性，高达90％。作为PowerShell 7的一部分，Microsoft在之前的日志记录基础上，增加了一种安全使用本地或远程存储中的凭据的方法，以便不需要将密码嵌入到脚本中。还将改进日志记录，以提供将本地计算机日志发送到远程设备的机制，而不管原始操作系统如何。                    

## Windows附带的PowerShell版本以及支持的最高版本

| **Windows**版本              | **Windows**包含的PowerShell版本 | **最高支持的PowerShell版本**               |
| ---------------------------- | ------------------------------- | ---------------------------------------- |
| Windows   Vista（SP2）       | 2.0                             | 2.0                                      |
| Windows   Server 2008（SP2） | 2.0                             | 3.0                                      |
| Windows   7（SP1）           | 2.0                             | 5.1                                      |
| Windows   2008 R2（SP1）     | 5.1                             | 5.1                                      |
| Windows   8                  | 3.0                             | 5.1                                      |
| Windows   2012               | 3.0                             | 5.1                                      |
| Windows   8.1                | 4                               | 5.1                                      |
| Windows   2012 R2            | 4                               | 5.1                                      |
| Windows   10                 | 5                               | 5.1                                      |
| Windows   2016               | 5.1                             | 5.1                                      |

## 配置PowerShell事件记录

|            | 注册处                                                       | 组策略                                                       |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 模块记录   | 键：HKLM \ SOFTWARE \ Policies \ Microsoft \   Windows \ PowerShell \ ModuleLogging    名称：EnableModuleLogging    数据：1（DWORD）键：HKLM \ SOFTWARE \ Policies \ Microsoft \   Windows \ PowerShell \ ModuleLogging \ ModuleNames    名称：[ModulePattern]    数据：[ModulePattern ]（REG_SZ）请参阅上面的屏幕截图，例如有关模块记录的信息。 | 策略\管理模板\   Windows组件\ Windows PowerShell \打开模块日志记录 |
| 脚本块记录 | 密钥：HKLM \ SOFTWARE \ Policies \ Microsoft \   Windows \ PowerShell \ ScriptBlockLogging     名称：EnableScriptBlockLogging     数据：1（DWORD） | 策略\管理模板\   Windows组件\ Windows PowerShell \脚本块日志记录 |

## Powershell常见事件ID及含义 

| 活动ID | 关联 | 审计                                                     | 笔记                                                         |
| ------ | ---- | -------------------------------------------------------- | ------------------------------------------------------------ |
| 400    | 403  | 始终记录，无论记录设置如何                               | 引擎状态从无更改为可用，记录任何本地或远程PowerShell活动的开始； |
| 403    | 400  | 始终记录，无论记录设置如何                               | 引擎状态从可用状态更改为停止，记录PowerShell活动结束。       |
| 500    | 501  | 在profile.ps1中需要$   LogCommandLifeCycleEvent = $ true | 命令“Write-Host”已启动。                                     |
| 501    | 500  | 在profile.ps1中需要$   LogCommandLifeCycleEvent = $ true | 命令“Write-Host”已停止。                                     |
| 600    | 500  | 始终记录，无论记录设置如何                               | 记录类似“WSMan”等提供程序在系统上进行PowerShell处理活动的开始，比如”Provider WSMan Is Started“； |
| 800    | 500  | ModuleLogging                                            | 命令行的管道执行细节：写入主机测试。                         |

| 活动ID | 关联 | 审计                       | 笔记                                                         |
| ------ | ---- | -------------------------- | ------------------------------------------------------------ |
| 4100   |      |                            | PowerShell遇到错误时记录                                     |
| 4103   |      | ModuleLogging              | 执行管道                                                     |
| 4104   |      | ScriptBlockLogging         | 执行远程命令   创建Scriptblock文本（1/1）： Write-Host   PowerShellV5ScriptBlockLogging |
| 40961  |      | 始终记录，无论记录设置如何 | PowerShell控制台正在启动                                     |
| 40962  |      | 始终记录，无论记录设置如何 | PowerShell控制台已准备好进行用户输入                         |

参考链接：

https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html

http://blog.nsfocus.net/attacks-defenses-powershell-event-logging/

<https://www.powershellmagazine.com/2014/07/16/investigating-powershell-attacks/>

 

推荐事件ID查询：

<https://docs.microsoft.com/en-us/previous-versions/tn-archive/dd639428(v=technet.10)>

<https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx>

强力推荐事件ID查询站点：

<https://www.myeventlog.com/search/find>

https://kb.eventtracker.com/



**如果你有更好的想法，可以及时与我联系！**
