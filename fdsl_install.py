#!/usr/bin/env python3
import os, sys, platform
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
        files, "freenet/lib/fn_utils.so", cflags, debug=False,
        is_shared=True
    )


def get_python_cflags():

    fd = os.popen("python3-config --includes --ldflags")
    s = fd.read()
    fd.close()

    s=s.replace("\r"," ")
    s=s.replace("\n"," ")

    major=str(sys.version_info.major)
    minor=str(sys.version_info.minor)

    s+=" -lpython%s.%s" % (major,minor)

    return s


def build_client(cflags, gw_mode=False):
    cflags += " -O3 -Wall"
    __build_fn_utils(cflags)


def main():
    help_doc = """
    [python3_include]
    """

    argv = sys.argv[1:]

    if len(argv) == 0:
        cflags = get_python_cflags()
    else:
        cflags = " ".join(argv)

    os_type = platform.system().lower()

    if os_type not in ("linux","darwin"):
        print("ERROR:not support your platform")
        return

    build_client(cflags, gw_mode=False)


if __name__ == '__main__':
    main()
