class ProxyByteArray(bytearray):
    def __init__(self, inner_buffer: bytearray | bytes):
        self._bytearray = bytearray(len(inner_buffer))
        for i in range(0, len(inner_buffer)):
            self._bytearray[i] = inner_buffer[i]
    
    def __enter__(self):
        # add things to say why doing this is important. 
        # reference nist.
        # talk about how bytearrays are modifiable and need to be cleared after so a `bytes` is not enough
        # talk about read only memory views to be returned to callers.
        # discuss clearing memory
        self._mem = memoryview(self._bytearray)
        
        return self._mem.toreadonly()

    def __exit__(self, exception_type, exception_value, exception_traceback):
        for i in range(0, len(self._mem)):
            self._mem[i] = 0x00
        # print(self._B.hex()) # proof that the data is destroyed
        self._bytearray = None
        self._mem = None
        # print("everything destroyed") # debug

