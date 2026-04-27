#!/usr/bin/env python3
import os, sys, platform, subprocess
import pywind.lib.sys_build as sys_build


def __is_mac_os():
    """检查是否为mac os系统"""
    if platform.system().lower().find("darwin") >= 0: return True
    return False


def __build_fn_utils(cflags):
    files = ["freenet/lib/fn_utils.c", "pywind/clib/netutils.c"]

    if __is_mac_os():
        files += ["freenet/lib/darwin.c"]
        cflags += " -DDarwin "
    sys_build.do_compile(
        files, "freenet/lib/fn_utils.so", cflags,
        is_shared=True
    )


def get_python_cflags():
    result = subprocess.run("python3-config --includes --ldflags", capture_output=True, shell=True)
    s = result.stdout.decode("utf-8")

    s = s.replace("\r", " ")
    s = s.replace("\n", " ")

    major = str(sys.version_info.major)
    minor = str(sys.version_info.minor)

    s += " -lpython%s.%s" % (major, minor)

    return s


def build_client(cflags):
    cflags += " -O3 -Wall -g"
    __build_fn_utils(cflags)


def main():
    help_doc = """
    [CFLAGS]
    """

    argv = sys.argv[1:]

    if len(argv) == 0:
        cflags = get_python_cflags()
    else:
        cflags = " ".join(argv)

    os_type = platform.system().lower()

    if os_type not in ("linux", "darwin"):
        print("ERROR:not support your platform")
        return

    build_client(cflags)


if __name__ == '__main__':
    main()
