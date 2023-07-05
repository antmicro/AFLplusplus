
import afl_renode
import ctypes

from afl_renode import INFD, read, monitor, visited, STATUS_ABORT, STATUS_SUCCESS


IDLE_COUNT = 4

DATA_SIZE = 1
data = ctypes.create_string_buffer(DATA_SIZE)

def quantum_hook():
    if len(visited) < IDLE_COUNT:
        n = read(INFD, data, DATA_SIZE)
        for byte in bytearray(data.raw[:n]):
            monitor.Machine["sysbus.i2c0"].InjectRxByte(byte)
        if n == 0:
            if len(afl_renode.visited) == 1:
                afl_renode.status = STATUS_ABORT
            else:
                afl_renode.status = STATUS_SUCCESS

afl_renode.quantum_hook = quantum_hook
