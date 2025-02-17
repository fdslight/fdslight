#!/usr/bin/env python3
import os, sys, platform
import pywind.lib.sys_build as sys_build


def __build_fn_utils(cflags):
    sys_build.do_compile(
        ["freenet/lib/fn_utils.c", "pywind/clib/netutils.c"], "freenet/lib/fn_utils.so", cflags, debug=False,
        is_shared=True
    )


def find_python_include_path():
    files = os.listdir("/usr/include")
    result = ""

    for f in files:
        p = f.find("python3")
        if p < 0: continue
        result = "/usr/include/%s" % f
        break

    return result


def build_client(cflags, gw_mode=False):
    cflags += " -O3 -Wall"
    __build_fn_utils(cflags)


def main():
    help_doc = """
    [python3_include]
    """

    argv = sys.argv[1:]

    if len(argv) == 0:
        py_include = find_python_include_path()
    else:
        py_include = argv[0]

    if not os.path.isdir(py_include):
        print("ERROR:not found python header file %s" % py_include)
        return

    cflags = " -I %s" % py_include

    os_type = platform.system().lower()

    if os_type not in ("linux",):
        print("ERROR:not support your platform")
        return

    build_client(cflags, gw_mode=False)


if __name__ == '__main__':
    main()
