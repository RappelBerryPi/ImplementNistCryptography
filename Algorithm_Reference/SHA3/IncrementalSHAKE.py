from enum import Enum
import sys
sys.path.append("../")
import SHA3.Keccak
import hashlib

# Thanks FIPS 203

class ShakeContext:
    def __init__(self):
        self.input = bytearray()
        self.outputAlreadyReturned = 0
        self.bufferRequestSize = 2000 #bytes
        self.buffer = bytearray()
        self.squeezeCalledPreviously = False
    
    def __str__(self):
        returnString =  "Context:\n"
        returnString += "\tOutputAlreadyReturned  : " + str(self.outputAlreadyReturned) + "\n"
        returnString += "\tbuffer                 : " + str(self.buffer) + "\n"
        returnString += "\tbuffer (len)           : " + str(len(self.buffer)) + "\n"
        returnString += "\tsqueezeCalledPreviously: " + str(self.squeezeCalledPreviously) + "\n"
        return returnString

class KnownEncodings(Enum):
    UTF8 = 'utf-8'
    RAW = "raw"

class IncrementalSHAKE:
    def __init__(self):
        # testing out hashlib as generation of matrix with hand built code is... slow
        self.SHA3 = SHA3.Keccak.SHA3(1600)
        self.SHA3_2 = hashlib.shake_256()
        self.shakeSize = 0
    
    def init(self):
        return ShakeContext()
    
    def absorbStr(self, ctx: ShakeContext, input: str, encoding: KnownEncodings = KnownEncodings.UTF8):
        if (ctx.squeezeCalledPreviously):
            raise RuntimeError("Absorb is not able to be called after calling squeeze")
        return self.absorb(ctx, bytearray(input, encoding.value))

    def absorb(self, ctx: ShakeContext, input: bytearray):
        if (ctx.squeezeCalledPreviously):
            raise RuntimeError("Absorb is not able to be called after calling squeeze")
        ctx.input.extend(input)
        return ctx
    
    def squeeze(self, ctx: ShakeContext, bytesRequested: int):
        returnBytes = b""
        if (not ctx.squeezeCalledPreviously):
            self.SHA3_2.update(ctx.input)
            # copied from keccak.py
            M = self.SHA3.convertToBitArray(ctx.input)
            M.append(1)
            M.append(1)
            M.append(1)
            M.append(1)
            ctx.input = M


        ctx.squeezeCalledPreviously = True

        # if going past end of buffer, get more
        while ((ctx.outputAlreadyReturned + bytesRequested) > len(ctx.buffer)):
            # d = bits,
            # d*8 = bytes

            # need to fully call Keccak_c every time. so must request current size + new buffer 
            # d = 8 * (len(ctx.buffer) + ctx.bufferRequestSize)
            #  ctx.buffer = self.SHA3.Keccak_c(self.shakeSize * 2, ctx.input, d)
            d = (len(ctx.buffer) + ctx.bufferRequestSize)
            ctx.buffer = self.SHA3_2.digest(d)

        
        returnBytes = ctx.buffer[ctx.outputAlreadyReturned:(ctx.outputAlreadyReturned+bytesRequested)]
        ctx.outputAlreadyReturned += bytesRequested

        return ctx, returnBytes

class IncrementalSHAKE128(IncrementalSHAKE):
    def __init__(self):
        super().__init__()
        self.shakeSize = 128
        self.SHA3_2 = hashlib.shake_128()

class IncrementalSHAKE256(IncrementalSHAKE):
    def __init__(self):
        super().__init__()
        self.shakeSize = 256
        self.sha3_2 = hashlib.shake_256()


if __name__ == "__main__":
    XOF = IncrementalSHAKE128()
    ctx = XOF.init()
    ctx = XOF.absorbStr(ctx, "abc", KnownEncodings.UTF8)
    ctx, output = XOF.squeeze(ctx, 1000)
    ctx, output = XOF.squeeze(ctx, 3)
    print(output)
