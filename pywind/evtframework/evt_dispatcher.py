#!/usr/bin/env python3

import pywind.evtframework.event as evt_notify
import pywind.evtframework.excepts as excepts
import pywind.lib.timer as timer
from pywind.global_vars import global_vars


class dispatcher(object):
    # handler集合,元素格式为 {fd:handler_object,...}
    __handlers = {}
    __poll = None
    __timer = None

    __loop_tasks = None

    __default_io_wait_time = None
    __debug = None

    def __init__(self, debug=False):
        self.__debug = debug
        global_vars["pyw.ioevtfw.dispatcher"] = self
        self.__default_io_wait_time = 10

    def create_handler(self, creator_fd, handler, *args, **kwargs):
        """ 创建一个处理者
        :param ns: 命名空间
        :param handler: 处理者
        :return:
        """
        instance = handler()
        fd = instance.init_func(creator_fd, *args, **kwargs)
        # 避免多个相同-1实例存在
        if fd < 0: return fd

        self.__handlers[fd] = instance

        return fd

    def repleace_handler(self, creator_fd, fileno, handler, *args, **kwargs):
        if fileno not in self.__handlers: raise excepts.HandlerNotFoundErr

        h = self.__handlers[fileno]
        h.release_when_replace()

        fd = self.create_handler(creator_fd, handler, *args, **kwargs)

        if fd < 0: return -1

        new_h = self.__handlers[fd]
        new_h.reader._putvalue(h.reader.read())
        new_h.writer.write(h.writer._getvalue())

        return fd

    def delete_handler(self, fd):
        """删除处理者
        :param fd: 文件描述符
        :return:
        """
        if fd not in self.__handlers: return

        if self.__timer.exists(fd): self.__timer.drop(fd)
        handler = self.__handlers[fd]
        handler.delete()
        self.del_loop_task(fd)

        del self.__handlers[fd]

    def set_timeout(self, fd, seconds):
        if seconds < 0:
            self.__timer.drop(fd)
            return
        self.__timer.set_timeout(fd, seconds)

    def register(self, fd):
        self.__poll.register(fd, evt_notify.EV_TYPE_NO_EV)

    def add_evt_read(self, fd):
        self.__poll.add_event(fd, evt_notify.EV_TYPE_READ)

    def remove_evt_read(self, fd):
        self.__poll.remove_event(fd, evt_notify.EV_TYPE_READ)

    def add_evt_write(self, fd):
        self.__poll.add_event(fd, evt_notify.EV_TYPE_WRITE)

    def remove_evt_write(self, fd):
        self.__poll.remove_event(fd, evt_notify.EV_TYPE_WRITE)

    def unregister(self, fd):
        self.__poll.unregister(fd)

    def myloop(self):
        """重写这个方法,添加你自己需要的循环执行代码"""
        pass

    def ioloop(self, *args, **kwargs):
        """
        :param args: 传递给self.init_func的参数
        :param kwargs: 传递给self.init_func的参数
        :return:
        """

        self.__timer = timer.timer()
        self.init_func(*args, **kwargs)

        while 1:
            wait_time = self.__timer.get_min_time()

            if wait_time > self.__default_io_wait_time: wait_time = self.__default_io_wait_time
            if wait_time < 1: wait_time = self.__default_io_wait_time
            if self.__loop_tasks: wait_time = 0

            event_set = self.__poll.poll(wait_time)

            self.__handle_events(event_set)
            self.__handle_timeout()
            self.__handle_loop_tasks()

            self.myloop()

        return

    def init_func(self, *args, **kwargs):
        """初始化函数,在调用IOLOOP之前调用,重写这个方法
        :return:
        """
        pass

    def init_func_after_fork(self):
        """fork 之后的第一个调用的函数,此函数只针对POSIX系统,重写这个方法
        :return:
        """
        pass

    def get_handler(self, fd):
        return self.__handlers.get(fd, None)

    def send_message_to_handler(self, src_fd, dst_fd, data):
        if dst_fd not in self.__handlers:
            raise excepts.HandlerNotFoundErr

        handler = self.__handlers[dst_fd]
        handler.message_from_handler(src_fd, data)

        return True

    def handler_exists(self, fd):
        return fd in self.__handlers

    def create_poll(self, *args, **kwargs):
        self.__poll = evt_notify.event(*args, **kwargs)

    def __handle_timeout(self):
        fd_set = self.__timer.get_timeout_names()

        for fd in fd_set:
            if self.__timer.exists(fd): self.__timer.drop(fd)
            if fd in self.__handlers:
                handler = self.__handlers[fd]
                handler.timeout()
            ''''''
        return

    def __handle_events(self, evt_set):
        for fd, evt, udata in evt_set:
            is_read = (evt & evt_notify.EV_TYPE_READ) == evt_notify.EV_TYPE_READ
            is_write = (evt & evt_notify.EV_TYPE_WRITE) == evt_notify.EV_TYPE_WRITE

            # 别的handler可能删除这个handler,因此需要检查
            if fd not in self.__handlers: continue
            handler = self.__handlers[fd]
            if not self.handler_exists(fd): continue

            if not self.handler_exists(fd): continue
            if is_read: handler.evt_read()
            if not self.handler_exists(fd): continue
            if is_write: handler.evt_write()
            ''''''
        return

    def __handle_loop_tasks(self):
        if not self.__loop_tasks: return
        fd_set = []
        for fileno in self.__loop_tasks: fd_set.append(fileno)
        for fileno in fd_set:
            handler = self.get_handler(fileno)
            handler.task_loop()
        return

    def ctl_handler(self, src_fd, dst_fd, cmd, *args, **kwargs):
        if dst_fd not in self.__handlers:
            raise excepts.HandlerNotFoundErr

        h = self.get_handler(dst_fd)
        return h.handler_ctl(src_fd, cmd, *args, **kwargs)

    def add_to_loop_task(self, fileno):
        """加入循环任务,即系统会循环调用handler.task_loop()"""
        if not self.__loop_tasks: self.__loop_tasks = {}
        if fileno in self.__loop_tasks: return
        self.__loop_tasks[fileno] = None

    def del_loop_task(self, fileno):
        """删除循环任务"""
        if not self.__loop_tasks: return
        if fileno in self.__loop_tasks: del self.__loop_tasks[fileno]

    def set_default_io_wait_time(self, seconds):
        """设置默认IO等待时间
        :param seconds:
        :return:
        """
        self.__default_io_wait_time = seconds
