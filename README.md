#### **IP层代理软件功能说明**

1. 使用分发规则：DNS名单内和指定IP使用代理,指定IP外使用代理
2. 服务端使用ixc_ProxyServd软件,本软件不再包含,地址 https://github.com/fdslight/ixc_ProxyServd
3. 每个版本rules是固定的，请下载版本后从实时源码中下载rules

#### **pip依赖**

1. pip install dnspython3
2. pip install cryptography

#### **Linux启动停止**

1. 先执行python3 fdsl_install.py \[CFLAGS\]
2. 默认代理方式:sudo python3 fdsl_client.py -d debug | start | stop -m local -c  your_configure_directory_name_at_fdslight_directory
3. 代理全部IPv6流量:sudo python3 fdsl_client.py -d debug | start | stop -m proxy_all_ipv6 -c  your_configure_directory_name_at_fdslight_directory
4. 代理全部IPv4流量:sudo python3 fdsl_client.py -d debug | start | stop -m proxy_all_ipv4 -c  your_configure_directory_name_at_fdslight_directory
#### **Windows启动停止**

1. Windows不需要安装
2. 复制fdslight_etc目录到fdslight目录下作为你的新配置文件目录,比如my_conf
3. 修改配置文件后执行python fdsl_conf_cipher.py encrypt进行配置文件加密(Linux系统不需要配置文件加解密)
4. 如果需要重新修改配置文件,请执行python fdsl_conf_cipher.py decrypt进行解密,修改完毕后再执行加密脚本
4. 复制fdslight-sample.bat脚本为自己的脚本名,例如fdslight-win.bat,并修改里面的配置目录
5. 双击fdslight-win.bat启动,并按照提示输入配置文件解密密钥

#### **注意事项**

1. 网络改变时可能会导致程序退出，比如网线插拔，当网络改变时可能需要重启程序