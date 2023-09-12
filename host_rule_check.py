#!/usr/bin/env python3
# 核对主机规则

import os, sys

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import freenet.lib.host_match as match
import freenet.lib.file_parser as file_parser


def check():
    fpath = "%s/fdslight_etc/host_rules.txt" % BASE_DIR
    rules = file_parser.parse_host_file(fpath)
    matcher = match.host_match()

    for rule in rules:
        is_match, flags = matcher.match(rule[0])

        if is_match:
            print("conflict rule %s" % rule[0])
            continue

        matcher.add_rule(rule)
    return

def main():
    check()

if __name__ == '__main__': main()
