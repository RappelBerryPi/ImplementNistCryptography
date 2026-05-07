from enum import Enum
import Keccak

# Thanks FIPS 203

class ShakeContext:
    def __init__(self):
        self.input = bytearray()
        self.outputAlreadyReturned = 0
        self.bufferRequestSize = 1000 #bytes
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


class IncrementalSHAKE128:
    def __init__(self):
        self.SHA3 = Keccak.SHA3(1600)
    
    def init(self):
        return ShakeContext()
    
    def absorb(self, ctx: ShakeContext, input: str, encoding: KnownEncodings = KnownEncodings.UTF8):
        if (ctx.squeezeCalledPreviously):
            raise RuntimeError("Absorb is not able to be called after calling squeeze")
        return self.absorb(ctx, bytearray(input, encoding.value))

    def absorb(self, ctx: ShakeContext, input: bytearray):
        if (ctx.squeezeCalledPreviously):
            raise RuntimeError("Absorb is not able to be called after calling squeeze")
        ctx.input.extend(input)
        return ctx
    
    def squeeze(self, ctx: ShakeContext, bytesRequested: int):
        shakeSize = 128
        returnBytes = b""
        if (not ctx.squeezeCalledPreviously):
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
            d = 8 * (len(ctx.buffer) + ctx.bufferRequestSize)

            ctx.buffer = self.SHA3.Keccak_c(shakeSize * 2, ctx.input, d)
        
        returnBytes = ctx.buffer[ctx.outputAlreadyReturned:(ctx.outputAlreadyReturned+bytesRequested)]
        ctx.outputAlreadyReturned += bytesRequested

        return ctx, returnBytes


if __name__ == "__main__":
    XOF = IncrementalSHAKE128()
    ctx = XOF.init()
    ctx = XOF.absorb(ctx, "abc")
    ctx, output = XOF.squeeze(ctx, 1000)
    ctx, output = XOF.squeeze(ctx, 3)
    print(output)
