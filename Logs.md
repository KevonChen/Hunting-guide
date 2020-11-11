# 日志详解

在安全分析过程中，可能要面对不同的数据源，如果不熟悉日志数据源格式，那么对于分析人员的分析工作可能会产生影响。

主要从**流量**、**终端日志**、**中间件日志**、**安全设备日志**四个部分进行收集，欢迎补充。


## 0x1 流量协议

HTTP协议：<https://www.cnblogs.com/li0803/archive/2008/11/03/1324746.html>

FTP协议：<https://www.cnblogs.com/luoxn28/p/5585458.html>

SMTP协议：<https://blog.csdn.net/sinat_36219858/article/details/71069515>

POP3协议：<https://blog.csdn.net/u014558484/article/details/53150038>

IMAP协议：<https://blog.csdn.net/u014608280/article/details/88536891>

SSH协议：<https://segmentfault.com/a/1190000011395818>

TELNET协议：<https://www.cnblogs.com/dazhaxie/archive/2012/06/27/2566054.html>

DNS协议：<https://blog.csdn.net/tianxuhong/article/details/74922454>

ICMP协议：<https://www.linuxidc.com/Linux/2018-09/154369.htm>

待补充

经典推荐：**《TCP/IP详解卷1：协议》 《TCP/IP详解·卷2：实现》 《TCP-IP详解卷3：TCP事务协议》**

## 0x2 终端日志

Windows_sysmon：<https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

windows_security：<https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688>

windows_powershell：<https://github.com/12306Bro/Hunting-guide/blob/master/Powershell-id.md>

Windows安全事件日志库：<https://www.manageengine.com/products/active-directory-audit/kb/windows-event-log-id-list.html?tab=System>

Linux_audit日志：<https://www.cnblogs.com/xingmuxin/tag/audit/>

Linux_audit理解审核日志文件：<https://access.redhat.com/documentation/zh-cn/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files>

linux下ssh登陆日志文件secure分析：<https://www.imzcy.cn/1274.html>

Linux日志文件（常见）及其功能：<http://c.biancheng.net/view/1097.html>

FTP日志详解：<https://www.ktanx.com/blog/p/362>

## 0x3 中间件日志

Apache日志参考：<https://zhuanlan.zhihu.com/p/138647322>

Nginx日志格式log_format详解（总结）：<http://www.ha97.com/5879.html>

Nginx日志格式详解：<https://blog.mimvp.com/article/29756.html>

Tomcat访问日志详解：<https://www.yuanmas.com/info/jvO61YjRy2.html>

Tomcat日志详解：<http://r6d.cn/CzMj>

weblogic日志介绍：<https://www.bbsmax.com/A/GBJrMbREz0/>

基于攻击流量和日志对Weblogic各类漏洞的分析思路：<http://www.0xby.com/1435.html>

网站服务器日志(IIS与Apache)各字段含义：<https://www.googlenb.com/info/53.html>

一招教你学会看网站IIS日志参数：<https://zhuanlan.zhihu.com/p/38567901>

## 0x4 安全设备日志

阿里云-Anti-Bot爬虫风险管理日志：<https://www.alibabacloud.com/help/zh/doc-detail/100127.htm?spm=a2c63.p38356.a1.1.62d8716dNcZRu2>

阿里云-云防火墙日志：<https://help.aliyun.com/document_detail/119874.html>

阿里云-web应用防火墙日志：<https://help.aliyun.com/document_detail/95492.html>

**其他厂商日志待补充**