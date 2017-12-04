### 测试流程（需要安装mininet）
网络拓扑结构
```
10.21.0.1/16    10.21.0.254/16 159.226.39.43/24    159.226.39.123/24
    
    h1       ------->        n1         ------->         h2
```
1 使用`make`构建项目

```shell
make
```

2 运行网络拓扑

```shell
python nat_topo.py
```

3 在n1上运行NAT程序
  
```shell
xterm n1
./scripts/disable_arp.sh
./scripts/disable_icmp.sh
./scripts/disable_ip_forward.sh 禁止协议栈的相应功能
export LD_LIBRARY_PATH=.
./nat
```
4 在h2上运行HTTP服务
 
```shell
xterm h2
./scripts/disable_offloading.sh
python -m SimpleHTTPServer
```
5 在h1上访问h2的HTTP服务

```shell
xterm h1
./scripts/disable_offloading.sh
wget http://159.226.39.123:8000
```
  

