#!/usr/bin/env python3
# https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt

import subprocess, os, time


def generate(src_path, dst_path, adds: list, suffix):
    up_time = time.strftime("# %Y-%m-%d %H:%M:%S %Z\n\n")
    dst = open(dst_path, "w")
    dst.write(up_time)

    for name, value in adds:
        dst.write(name + ":" + str(value) + "\n")
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
    ext_rules = [
        ("*", 1),
        ("*.freekai.net", 3),
        ("*.wss.ws", 3),
    ]
    generate("chinamax_domain.txt", "host_rules.txt", ext_rules, "3")


if __name__ == "__main__":
    main()
