#!/usr/bin/env python3
# 守护程序,程序意外退出时自动重启
import getopt, os, sys, signal, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import freenet.lib.proc as proc

PROXY_PID_PATH = "/tmp/fdslight.pid"
MYPID_PATH = "/tmp/fdslight_monitor.pid"


def stop_myself():
    if not os.path.isfile(MYPID_PATH):
        print("ERROR:not found fdsl_monitor process")
        return

    pid = proc.get_pid(MYPID_PATH)
    if pid < 0: return
    try:
        os.kill(pid, signal.SIGINT)
    except:
        pass

    os.remove(MYPID_PATH)


def stop_proxy():
    cmd = "%s %s/fdsl_client.py -d stop" % (sys.executable, BASE_DIR,)
    os.system(cmd)


def start_proxy(mode, conf_dir):
    cmd = "%s %s/fdsl_client.py -d start -m %s -c %s" % (sys.executable, BASE_DIR, mode, conf_dir)
    os.system(cmd)


def start(mode, conf_dir):
    pid = os.fork()
    if pid != 0: sys.exit(0)

    up_time = time.time()
    is_exited = False

    proc.write_pid(MYPID_PATH)

    try:
        while 1:
            if not is_exited: up_time = time.time()
            if not os.path.isfile(PROXY_PID_PATH):
                if not is_exited:
                    is_exited = True
                    continue
                now = time.time()
                if now - up_time >= 10:
                    start_proxy(mode, conf_dir)
                    is_exited = False
                ''''''
            time.sleep(10)
        ''''''
    except KeyboardInterrupt:
        stop_proxy()


def main():
    help_doc = """
    -d      start | stop
    -m      local | gateway | proxy_all_ipv4 | proxy_all_ipv6 
    -c      set config directory,default is fdslight_etc
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "m:d:c:", [])
    except getopt.GetoptError:
        print(help_doc)
        return
    m = ""
    c = ""
    d = ""

    for k, v in opts:
        if k == "-m": m = v
        if k == "-c": c = v
        if k == "-d": d = v

    if d not in ("start", "stop",):
        print(help_doc)
        return

    if d == "stop":
        stop_myself()
        return

    if m not in ("local", "gateway", "proxy_all_ipv4", "proxy_all_ipv6",):
        print(help_doc)
        return

    if not c:
        c = "%s/fdslight_etc" % BASE_DIR

    if not os.path.isdir(c):
        print("ERROR:configure %s not is a directory" % c)
        return

    start(m, c)


if __name__ == '__main__': main()
