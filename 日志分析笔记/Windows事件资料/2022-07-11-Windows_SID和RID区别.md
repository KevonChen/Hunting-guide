# Windows的SID和RID

关于SID和RID的文章有很多，为什么要写这篇文章（tips:瞎攒一份）？其实在我们进行安全数据分析的时候，经常会遇到日志源无法满足模型建设的问题，那么我们能够放弃这个模型么？不能啊！！！甲方粑粑不允许啊！所以我们要对模型进行调整，使模型满足当前日志源质量，对模型进行调整就会带来准确度就会下降，误报率上升的问题。在排除误报时，这些SID会给我们很大的帮助。

## SID

SID安全标识符（Security Identifiers），是标识用户、组和计算机帐户的唯一的号码。在第一次创建该帐户时，将给网络上的每一个帐户发布一个唯一的SID。Windows 2000中的内部进程将引用帐户的`SID`而不是帐户的用户或组名。如果创建帐户，再删除帐户，然后使用相同的用户名创建另一个帐户，则新帐户将不具有授权给前一个帐户的权力或权限，原因是该帐户具有不同的`SID`号。安全标识符也被称为`安全ID`或`SID`。

### SID作用

用户通过验证后，登陆进程会给用户一个访问令牌，该令牌相当于用户访问系统资源的票证，当用户试图访问系统资源时，将访问令牌提供给Windows NT，然后Windows NT检查用户试图访问对象上的访问控制列表。如果用户被允许访问该对象，Windows NT将会分配给用户适当的访问权限。

访问令牌是用户在通过验证的时候有登陆进程所提供的，所以改变用户的权限需要注销后重新登陆，重新获取访问令牌。

### SID号码的组成

如果存在两个同样SID的用户，这两个帐户将被鉴别为同一个帐户，原理上如果帐户无限制增加的时候，会产生同样的SID，在通常的情况下SID是唯一的，他由计算机名、当前时间、当前用户态线程的CPU耗费时间的总和三个参数决定以保证它的唯一性。

一个完整的SID包括：

- 用户和组的安全描述
- 48-bit的ID authority
- 修订版本
- 可变的验证值Variable sub-authority values

例：S-1-5-21-310440588-250036847-580389505-500 它遵循的模式是：S－R－IA－SA－SA－RID。下面是具体解释：

- 字母S指明这是一个SID标识符，它将数字标记为一个SID。
- R代表Revision（修订），Windows生成的所有SID都使用修订级别1。
- IA代表颁发机构。在Widnwos中，几乎所有SID都指定NT机构作为颁发机构，它的ID编号为5。代表已知组和账户的SID例外。
- SA代表一个子机构。SA指定特殊的组或职能。例如、21表明SID由一个域控制器或者一台单机颁发。随后的一长串数字（1683771068-12213551888-624655398）就是颁发SID的那个域或机器的SA。
- RID是指相对ID（RID）、是SA所指派的一个惟一的、顺序的编号、代表一个安全主体（比如一个用户、计算机或组）

插播重点知识：在经典NT和windows2000中，Local System账户SID S－1-5-18为几乎所有服务提供了安全上下文，该账户具有很大的特权。（在数据分析过程中你会经常看到它的身影）

### SID重复问题的产生

安装NT／2000系统的时候，产生了一个唯一的SID，但是当你使用类似Ghost的软件克隆机器的时候，就会产生不同的机器使用一个SID的问题。产生了很严重的安全问题。

同样，如果是重复的SID对于对等网来说也会产生很多安全方面的问题。在对等网中帐号的基础是SID加上一个相关的标识符（RID），如果所有的工作站都拥有一样的SID，每个工作站上产生的第一个帐号都是一样的，这样就对用户本身的文件夹和文件的安全产生了隐患。

这个时候某个人在自己的NTFS分区建立了共享，并且设置了自己可以访问，但是实际上另外一台机器的SID号码和这个一样的用户此时也是可以访问这个共享的。

## 关于RID

已知RID：指派给用户、计算机和组的RID从1000开始。500-999的RID被专门保留起来、表示在每个Windows计算机和域中通用的账户和组，它们称为“已知RID”，有些已知RID会附加到一个域SID上，从而构成一个惟一的标识符。另一些则附加到Builtin SID(S-1-5-32)上，指出它们是可能具有特权的Builtin账户－－特权要么是硬编码到操作系统中的，要么是在安全数据库中指派的。

## 关于RID劫持

每个帐户都有一个指定的RID来标识它。与域控制器不同，Windows工作站和服务器会将大部分数据存储在    `HKLM\SAM\SAM\Domains\Account\Users`项中，这需要访问System权限。它将通过设置一个相对标识符（RID）来更改帐户属性，该标识符应由目标机器上的一个现有账户拥有。利用一些Windows本地用户管理完整性的缺陷，该模块将允许使用一个已知帐户凭证（如GUEST帐户）进行身份验证，并使用另一个现有帐户（如Administrator帐户）的权限进行访问，即使禁用了Administrator账户。

RID劫持权限：需要system权限进行劫持，最好放在持久化部分。

参考链接：

关于RID相关的攻击手法：
<https://xz.aliyun.com/t/2998>

关于windows SID理解：
<https://www.cnblogs.com/jackydalong/p/3262241.html>

<https://www.cnblogs.com/mq0036/p/3518542.html>

关于windows SID解释：
<https://support.microsoft.com/zh-cn/help/243330/well-known-security-identifiers-in-windows-operating-systems>

<https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids>
