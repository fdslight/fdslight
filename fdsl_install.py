#!/usr/bin/env python3
import os
import sys
import shutil
import pywind.lib.sys_build as sys_build


def write_kern_ver_to_file(fpath):
    """写入内核版本到文件
    :param fpath:
    :return:
    """
    with open(fpath, "w") as f:
        popen = os.popen("uname -r")
        f.write(popen.read())
        popen.close()


def __build_fn_utils(cflags):
    sys_build.do_compile(
        ["freenet/lib/fn_utils.c", "pywind/clib/netutils.c"], "freenet/lib/fn_utils.so", cflags, debug=False,
        is_shared=True
    )


def __build_fdsl_ctl(cflags):
    sys_build.do_compile(
        ["driver/fdsl_dgram/py_fdsl_ctl.c"], "freenet/lib/fdsl_ctl.so", cflags, debug=False, is_shared=True
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
    __build_fdsl_ctl(cflags)

    if gw_mode:
        os.chdir("driver/fdsl_dgram")
        os.system("make clean")
        os.system("make")
        os.chdir("../../")
        write_kern_ver_to_file("./kern_version")
        if not os.path.isfile("driver/fdsl_dgram/fdslight_dgram.ko"):
            print("install fdslight failed!!!")
            return

        path = "driver/fdslight_dgram.ko"
        if os.path.isfile(path):
            os.remove(path)
        shutil.move("driver/fdsl_dgram/fdslight_dgram.ko", "driver")
    ''''''


def main():
    help_doc = """
    gateway | local [python3_include]
    """

    argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        print(help_doc)
        return

    mode = argv[0]

    if mode not in ("gateway", "local",):
        print("the mode must be gateway or local")
        return

    if len(argv) == 1:
        py_include = find_python_include_path()
    else:
        py_include = argv[1]

    if not os.path.isdir(py_include):
        print("ERROR:not found python header file %s" % py_include)
        return

    cflags = " -I %s" % py_include

    if mode == "gateway":
        build_client(cflags, gw_mode=True)
        return

    if mode == "local":
        build_client(cflags, gw_mode=False)


if __name__ == '__main__':
    main()
