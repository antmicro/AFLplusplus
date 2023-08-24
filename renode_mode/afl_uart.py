
import afl_renode
import ctypes

from afl_renode import INFD, read, monitor, visited, STATUS_ABORT, STATUS_SUCCESS


IDLE_COUNT = 4

DATA_SIZE = 1
data = ctypes.create_string_buffer(DATA_SIZE)
eof = False

def quantum_hook():
    global eof

    if len(visited) < IDLE_COUNT:
        n = read(INFD, data, DATA_SIZE)
        for byte in bytearray(data.raw[:n]):
            monitor.Machine["sysbus.usart4"].WriteChar(byte)
        if n == 0:
            if not eof:
                monitor.Machine["sysbus.usart4"].WriteChar(0x0a)
                eof = True
                return
            eof = False
            if len(afl_renode.visited) == 1:
                afl_renode.status = STATUS_ABORT
            else:
                afl_renode.status = STATUS_SUCCESS

afl_renode.quantum_hook = quantum_hook
