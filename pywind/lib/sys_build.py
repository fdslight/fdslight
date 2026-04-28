#!/usr/bin/env python3
import os, subprocess


def get_c_files(d):
    """ 获取C文件
    :param d:
    :return:
    """
    abs_dir = d

    dirs = os.listdir(abs_dir)
    results = []

    for s in dirs:
        p = "%s/%s" % (d, s,)
        if p[-1] not in ["c", "C", ]: continue
        if p[-2] != ".": continue

        results.append(p)

    return results


def get_c_files_from_dirs(d_list):
    rs = []
    for d in d_list:
        t = get_c_files(d)
        if not t: continue
        for s in t:
            if s not in rs: rs.append(s)

    return rs


def do_compile(flist, output, c_flags, is_shared=False):
    cc=os.getenv("CC")
    if cc is None: cc="cc"

    r=subprocess.run("which %s" % cc, shell=True, capture_output=True)
    s=r.stdout.decode("utf-8")

    if not s and not os.path.isfile(cc):
        print("ERROR: C compiler %s not found" % cc)
        return

    cmd = cc

    if is_shared:
        cmd += " -fPIC -shared"

    cmd += " %s -o %s" % (" ".join(flist), output,)

    if c_flags:
        cmd += " %s" % c_flags

    print(cmd)

    subprocess.call(cmd, shell=True)
