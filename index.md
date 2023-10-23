### 功能说明
客户端有两大模式，local模式和gateway模式，local模式是让本地机器走代理上网的，gateway模式是让局域网其他机器走智能代理的，local模式功能没gateway多，gateway模式支持局域网任何机器走代理，local模式只支持Linux。最后说明fdslight只能运行在Linux上

### 安装环境（以下教程是在Ubuntu16.04进行的）
Linux机器，客户端服务端都需要Linux，python3。

### 安装第一步（准备软件运行环境）
1.Python3说明：ubuntu自带的Python3可能会有点麻烦，最好自己编译python3,而且编译Python3也很简单  
2.Python3下载:wget https://www.python.org/ftp/python/3.5.4/Python-3.5.4.tgz  
3.解压Python3: tar zxf Python-3.5.4.tgz  
4.假设把Python3安装到/opt目录，你也可以选择其他目录，这里以/opt目录为例  
5.命令:cd Python-3.5.4  
6.命令:./configure --prefix=/opt --enable-ipv6  
7.命令:make -j2  
8.命令(如果提示要输入密码那么就输入密码):sudo make install  

### 安装第二步(安装软件的Python3依赖库)
1.首先需要安装python的dnspython和cryptography库，dnspython无论如何一定要，如果使用默认的加密方式，那么需要cryptography库  
2.命令：cd /opt/bin  
3.命令：sudo ./pip3 install dnspython3  
4.命令：sudo ./pip3 install cryptography  

### 服务端安装
1.首先进入下载的fdslight的目录,里面有个install.py文件  
2.命令：/opt/bin/python3 install.py server /opt/include/python3.5m

### 客戶端gateway模式安装
1.在ubuntu desktop版本下已经默认安装了linux headers,你不需要安装，如果不是ubuntu需要安装linux headers,即内核开发包，**如果你的机器更新了内核，你需要重新安装一次**  
2.进入下载的fdslight的目录  
3.命令：/opt/bin/python3 install.py gateway /opt/include/python3.5m  

### 客戶端local模式安装
1.进入下载的fdslight的目录  
2.命令：/opt/bin/python3 install.py local /opt/include/python3.5m  

### 安装完成后配置说明
1.文件结构请看fdslight项目源码上面的wiki页面，传送连接:https://github.com/fdslight/fdslight/wiki/ 一些文件结构说明  
2.请详细阅读配置文件注释，上面有给了每个配置选项的具体说明  

### 启动命令的说明("|"表示或的意思)  
sudo /opt/bin/python3 main.py -m server|gateway|local|proxy_all_ipv4|proxy_all_ipv6 -d start|debug|stop  

### 客户端gateway模式的特别说明  
1.网关模式本地机器无法通过代理，局域网的其他的机器可以走代理
2.要使局域网的其他机器可以走代理，你需要设置局域网其他机器的网关为运行fdslight客户端的地址，DNS也是fdslight客户端的地址

### 客户端local模式的特别说明(以ubuntu desktop发行版说明）
1.fn_client.ini文件有个virtual_dns选项，需要把主机的DNS改成这个DNS地址（如果是DHCP分配地址的方式，请把他改成只地址的选项，如下图）
![local配置图](https://github.com/fdslight/fdslight/blob/master/images/fdsl_local_config.png?raw=true)

2.改好之后需要断开网络然后重启网络，但是此时如果运行fdslight，或导致退出，无论如何，你都要重新启动或者启动fdslight，参考图  


![网络中断](https://github.com/fdslight/fdslight/blob/master/images/fdsl_local_chg_nw.png?raw=true)
