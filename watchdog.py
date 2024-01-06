#!/usr/bin/env python3
"""看门狗程序
"""
import sys, os, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)


def main():
    helper = """
        py_file_name pid_file script_args
    """

    size = len(sys.argv)
    if size < 2:
        print(helper)
        return

    if sys.argv[1] == "help":
        print(helper)
        return

    if size < 3:
        print(helper)
        return

    flags = False
    pid = os.fork()
    if pid != 0: sys.exit(0)

    os.setsid()
    os.umask(0)

    pid = os.fork()
    if pid != 0: sys.exit(0)

    pid_file = sys.argv[2]

    path = "%s/%s" % (BASE_DIR, sys.argv[1])
    if not os.path.isfile(path):
        sys.stderr.write("not found file %s\r\n" % path)
        return

    cmd = "%s %s %s" % (sys.executable, path, " ".join(sys.argv[3:]))

    while 1:
        if not os.path.isfile(pid_file):
            # 第一次执行的时候打印命令
            if not flags:
                flags = True
                print(cmd)
            os.system(cmd)
            # 进程启动以及生成pid文件需要时间,因此这里需要休眠
            time.sleep(60)
        time.sleep(30)


if __name__ == '__main__': main()
