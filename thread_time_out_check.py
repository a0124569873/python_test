#线程超时检测
thread_pool = {}

def check_threshold():
    global thread_pool

    def _async_raise(tid, exctype):
        """raises the exception, performs cleanup if needed"""
        tid = ctypes.c_long(tid)
        if not inspect.isclass(exctype):
            exctype = type(exctype)
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
        if res == 0:
            raise ValueError("invalid thread id")

        elif res != 1:
            # """if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect"""
            ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
            raise SystemError("PyThreadState_SetAsyncExc failed")

    def stop_thread(thread_id):
        _async_raise(thread_id, SystemExit)


    while True:
        for thread_id,create_time in thread_pool:
            if (int(time.time()) - create_time) >= conf["thread_timeout"]:
                stop_thread(thread_id)

        time.sleep(conf["check_thread_cycle_time"])
