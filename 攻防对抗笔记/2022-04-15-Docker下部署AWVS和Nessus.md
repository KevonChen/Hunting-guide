# Docker下部署AWVS和Nessus

## 声明
文章来自：[漏洞扫描—Awvs&Nessus(Docker版V3.0)–雷石安全](https://mp.weixin.qq.com/s?__biz=MzI5MDE0MjQ1NQ==&mid=2247498179&idx=2&sn=fa6f117c420bc52306508fe81af3b4d3&chksm=ec26d85bdb51514d6def0629e0c71ed5506b1939a9f69b30ff47d977fab8cc96dc15af16fb1c&mpshare=1&scene=23&srcid=1031d22NMZJcOV53f1sF2DPA&sharer_sharetime=1604139889173&sharer_shareid=ff83fe2fe7db7fcd8a1fcbc183d841c4#rd),雷石实验室维护的AWVS和Nessus镜像，可在[docker hub](https://hub.docker.com/r/leishianquan/awvs-nessus/tags?page=1&ordering=last_updated)上查看最新版本

## 安装
### 拉取镜像到本地
```
docker pull leishianquan/awvs-nessus:v4
```
### 启动
```
docker run -it -d -p 13443:3443 -p 8834:8834 leishianquan/awvs-nessus:v4
```

注意：nessus是需要进入容器启动的
查看容器
```bash
docker ps -a
```
启动容器
```bash
docker start 容器id
```
进入容器
```bash
docker exec -it 容器id bash
```
安装nessus时区
```bash
apt-get install tzdata:Asia/Shanghai
```
启动nessus服务
```bash
/etc/init.d/nessusd start
```
破解AWVS
```bash
cp /home/license_info.json /home/acunetix/.acunetix/data/license/
```

## 使用
### Nessus
```
https://127.0.0.1:8834/#/

nessus username:leishi

nessus password:leishianquan
```

### Awvs
```
https://127.0.0.1:13443/

awvs13 username: [leishi@leishi.com](mailto:leishi@leishi.com)

awvs13 password: Leishi123
```

## 参考链接
[AWVS和Nessus镜像安装](https://m01ly.github.io/2020/08/26/scan-awvs-nessus/)

[Docker安装AWVS和Nessus](https://www.cnblogs.com/hxlinux/p/14749230.html)
