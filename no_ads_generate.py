#!/usr/bin/env python3
# 生成广告屏蔽版本的代理规则文件
import os

URL = "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt"


def parse(fpath: str):
    fdst = open(fpath, "r")
    results = []

    for line in fdst:
        line = line.strip()
        line = line.replace("\n", "")
        line = line.replace("\r", "")
        if not line: continue
        if line[0] == "#": continue

        results.append(line)
    fdst.close()
    return results

def gen_proxy_rule(results):
    """生成代理规则
    """
    fdst = open("proxy_no_ads.txt", "w")
    fdst.write("\r\n\r\n### drop ads ###\r\n")

    for host in results:
        fdst.write("%s:2\r\n" % host)

    fdst.close()

def main():
    os.system("wget %s" % URL)
    results = parse("anti-ad-domains.txt")
    gen_proxy_rule(results)

if __name__ == '__main__': main()
