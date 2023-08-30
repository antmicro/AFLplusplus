
import afl_renode
import ctypes

from afl_renode import INFD, read, monitor, visited, STATUS_ABORT, STATUS_SUCCESS


IDLE_COUNT = 4

DATA_SIZE = 4096
data = ctypes.create_string_buffer(DATA_SIZE)

# replace I2C sensor definition with something like:
#     machine LoadPlatformDescriptionFromString "dummy_sensor: Mocks.DummyI2CSlave @ i2c0 0x30"

def quantum_hook(mach):
    if len(visited) < IDLE_COUNT:
        n = read(INFD, data, DATA_SIZE)
        for byte in bytearray(data.raw[:n]):
            mach["sysbus.i2c0.dummy_sensor"].EnqueueResponseByte(byte)
        if n == 0:
            if len(afl_renode.visited) == 1:
                afl_renode.status = STATUS_ABORT
            else:
                afl_renode.status = STATUS_SUCCESS

afl_renode.quantum_hook = quantum_hook
