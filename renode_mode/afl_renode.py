#!/usr/bin/env python

from __future__ import print_function

import ctypes, struct
import os, sys
import signal

# taken from AFL's config.h
FORKSRV_FD = 198
SHM_ENV_VAR = "__AFL_SHM_ID"
MAP_SIZE = 2 ** 16

try:
    shmid = int(os.environ[SHM_ENV_VAR])
except KeyError:
    print("Failed to detect AFL; proceeding anyway")
    shmid = -1

monitor_module = sys.modules['<module>']
monitor = monitor_module.monitor
emulationManager = monitor_module.emulationManager

try:
    libc = ctypes.CDLL("", use_errno=True)
except SystemError:
    print("Could not find libdl.so in system libraries or LD_LIBRARY_PATH.  This is likely caused by IronPython using wrong ABI location of libdl.so.2; try to install development headers for libc, or to create a symlink to libdl.so.2 named libdl.so as a workaround.")
    raise

shmat = libc.shmat
shmat.restype = ctypes.c_void_p
shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)

read = libc.read
read.restype = ctypes.c_ssize_t
read.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t)

write = libc.write
write.restype = ctypes.c_ssize_t
write.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t)


# replicated from <sys/wait.h> (namely <bits/waitstatus.h>)
def W_EXITCODE(ret, sig):
    return (ret << 8) | sig

STATUS_SUCCESS = W_EXITCODE(0, 0)
STATUS_SEGV = W_EXITCODE(0, signal.SIGSEGV)
STATUS_ABORT = W_EXITCODE(0, signal.SIGABRT)

INFD = FORKSRV_FD - 1

endgame = {0: STATUS_SEGV}
sysbus_name = "sysbus"


if shmid != -1:
    afl_mem = shmat(shmid, 0, 0)
    print('shmat mem =', hex(afl_mem))
    memp = ctypes.POINTER(ctypes.c_ubyte * MAP_SIZE)
    afl_mem = ctypes.cast(afl_mem, memp)

    arr = ctypes.create_string_buffer(4)
    try:
        # send 4 meaningless bytes, required by AFL forkserver protocol
        n = write(FORKSRV_FD + 1, arr, 4)
    except IOError:
        print("Failed to communicate with AFL?")
        raise


def do_one_fuzz():
    n = read(FORKSRV_FD, arr, 4)

    if n == 0:
        for cmd in monitor.RegisteredCommands:
            if cmd.Name == 'quit':
                cmd.Run(monitor.Interaction)
                return
        sys.exit(0)

    pid = os.getpid()
    arr.raw = struct.pack('i', pid)
    n = write(FORKSRV_FD + 1, arr, 4)
    afl_mem.contents[0] = 1
    do_one_child()


def do_one_child():
    global status
    for cpu in monitor.Machine[sysbus_name].GetCPUs():
        cpu.SetHookAtBlockBegin(log_basic_block)

    status = None
    monitor.Machine.LocalTimeSource.SinksReportedHook += do_quantum_hook
    emulationManager.CurrentEmulation.StartAll()


def one_fuzz_complete(status):
    arr.raw = struct.pack('i', status)
    n = write(FORKSRV_FD + 1, arr, 4)

    #monitor.Machine.Reset()
    do_one_fuzz()


def quantum_hook():
    '''
    This is the fuzzing harness.  Feel free to override it.
    '''
    if len(visited) < 4:
        afl_renode.status = STATUS_SUCCESS

visited = set()
def do_quantum_hook():
    quantum_hook()
    visited.clear()

    if status is not None:
        monitor.Machine.LocalTimeSource.SinksReportedHook -= do_quantum_hook
        one_fuzz_complete(status)
        return


def log_basic_block(pc, size):
    global status
    loc = hash((pc, size)) % MAP_SIZE
    visited.add(loc)
    afl_mem.contents[loc] += 1
    if pc in endgame:
        # defer cleanup and restart to avoid hangs
        status = endgame[pc]
        for cpu in monitor.Machine[sysbus_name].GetCPUs():
            cpu.ClearHookAtBlockBegin()


if shmid == -1:
    do_one_fuzz = do_one_child
    class afl_mem:
        contents = [0] * MAP_SIZE
    def one_fuzz_complete(status):
        print(afl_mem.contents)
        print("Exiting with status:", status)
        sys.exit(status)

print("AFL-Renode activated!")
