#!/usr/bin/env python3
# 生成广告屏蔽版本的代理规则文件
import os

URL = "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt"

# 核外加入的匹配规则
EXTRA_ADDS = [
    "*.gz-data.com",
]

# 去除一些规则
EXTRA_DROPS = [
    "google",
    "twitter",
    "facebook",
    "microsoft",
    "bing",
    ".qy.net",
    "doubleclick.net",
    "doubleclick.com",
    "sentry.io",
    "app-measurement",
    "cloudflare.com",
    ".stripe.com",
    ".tw",
    ".philips.",
    ".cloudfront.net",
    "amazonaws.com",
    ".amazon.",
    "americanexpress",
    ".windows.com",
    ".yahoo.com",
    ".yandex.ru",
    ".co.jp",
    ".dyson.",
    ".reddit.com",
    ".redditmedia.com",
    ".redhat.com",
    ".ricoh.",
    "marketo.net",

    "simba.taobao.com",
]


def parse(fpath: str):
    fdst = open(fpath, "r")
    results = []

    for line in fdst:
        line = line.strip()
        line = line.replace("\n", "")
        line = line.replace("\r", "")
        if not line: continue
        if line[0] == "#": continue

        is_matched = False
        for s in EXTRA_DROPS:
            p = line.find(s)
            if p >= 0:
                is_matched = True
                break
            ''''''
        if is_matched: continue

        results.append(line)
    fdst.close()
    return results


def gen_dns_rule(results):
    """生成DNS屏蔽规则
    """
    # 首先读取源文件
    fpath = "fdslight_etc/host_rules.txt"
    with open(fpath, "r", encoding="utf-8") as f:
        s = f.read()
    f.close()

    fname = "host_rules.txt"
    fdst = open(fname, "w")

    fdst.write(s)
    fdst.write("\n\n")
    fdst.write("###  Advertisement DNS DROP #####\n\n")

    for host in EXTRA_ADDS:
        fdst.write("%s:2\n" % host)

    for host in results:
        fdst.write("%s:2\n" % host)

    fdst.close()
    print("generate %s OK" % fname)


def main():
    fname = "anti-ad-domains.txt"
    if os.path.isfile(fname): os.remove(fname)
    os.system("wget %s" % URL)
    results = parse(fname)
    # gen_proxy_rule(results)
    gen_dns_rule(results)
    os.remove(fname)


if __name__ == '__main__': main()
