#!/usr/bin/env python3
# https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt
# 生成规则文件

import subprocess, os, time


def generate(src_path, dst_path, adds: list, suffix):
    up_time = time.strftime("# %Y-%m-%d %H:%M:%S\n")
    dst = open(dst_path, "w")
    dst.write(up_time)
    s = """
### --------------重要说明--------------------------
## 域名前缀的"*"表示匹配所有,"#"开头的表示注释
# ":0" 表示DNS走加密
# ":1" 表示解析DNS并且走代理
# ":2"表示丢弃DNS请求,可用于广告屏蔽等其他用途
# ":3"表示域名所对应的IP地址不走代理

###-------------------------------------------------
"""
    dst.write(s)
    dst.write("\n")

    for name, value in adds:
        dst.write(name + ":" + value + "\n")
    dst.write("\n")
    src = open(src_path, 'r')
    for line in src:
        line = line.strip()
        line = line.replace('\n', '')
        line = line.replace('\r', '')
        if not line: continue
        if line[0] == "#":
            dst.write(line + "\n")
            continue
        if line[0] == ".":
            new_line = "*" + line + ":%s" % suffix + "\n"
        else:
            new_line = line + ":%s" % suffix + "\n"
        dst.write(new_line)
    src.close()
    dst.close()

    print("generate file %s OK" % dst_path)


def main():
    fname = "chinamax_domain.txt"
    if os.path.isfile(fname): os.remove(fname)

    url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt"

    subprocess.call("curl %s -o chinamax_domain.txt" % url, shell=True)
    adds = [
        ("*", "1"),
    ]
    generate("chinamax_domain.txt", "host_rules.txt", adds, "3")


if __name__ == "__main__":
    main()
