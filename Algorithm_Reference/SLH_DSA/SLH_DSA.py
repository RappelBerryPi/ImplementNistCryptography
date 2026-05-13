from array import array
from abc import ABC

# addresses as described on page 11 -14
class Address(ABC):
    def __init__(self):
        self.layer_address = bytearray([0] * 4)
        self.tree_address = bytearray([0] * 12)
        self.type = bytearray([255] * 4)
    
    @property
    def layer_address(self) -> bytearray:
        return self._layer_address
    
    @layer_address.setter
    def layer_address(self, value: bytearray):
        self.layer_address = value[0:4].copy()
    
    @property
    def tree_address(self) -> bytearray:
        return self._tree_address
    
    @tree_address.setter
    def tree_address(self, value: bytearray):
        self.tree_address = value[0:12].copy()
    
    @property
    def address_type(self) -> bytearray:
        return self._address_type
    
    @address_type.setter
    def address_type(self, value: bytearray):
        self.address_type = value[0:4].copy()
    
    def as_bytearray(self):
        returnByteArray = bytearray()
        returnByteArray.extend(self.layer_address.copy())
        returnByteArray.extend(self.tree_address.copy())
        returnByteArray.extend(self.address_type.copy())
        returnByteArray.extend([0] * 12)
        return returnByteArray
    
class WOTS_Hash_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 0])
        self.key_pair_address = bytearray([0] * 4)
        self.chain_address = bytearray([0] * 4)
        self.hash_address = bytearray([0] * 4)
    
    @property
    def key_pair_address(self) -> bytearray:
        return self._key_pair_address
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.key_pair_address = value[0:4].copy()
    
    @property
    def chain_address(self) -> bytearray:
        return self._chain_address
    
    @chain_address.setter
    def chain_address(self, value: bytearray):
        self.chain_address = value[0:4].copy()

    @property
    def hash_address(self) -> bytearray:
        return self._hash_address

    @hash_address.setter
    def hash_address(self, value: bytearray):
        self.hash_address = value[0:4].copy()
    
    def as_bytearray(self):
        returnByteArray = super().as_bytearray()
        returnByteArray = returnByteArray[-12:]
        returnByteArray.extend(self.key_pair_address.copy())
        returnByteArray.extend(self.chain_address.copy())
        returnByteArray.extend(self.hash_address.copy())
        return returnByteArray
    
class WOTS_PK_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 1])
        self.key_pair_address = bytearray([0] * 4)
        self.padding = bytearray([0] * 8)

    @property
    def key_pair_address(self) -> bytearray:
        return self._key_pair_address
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.key_pair_address = value[0:4].copy()

    @property
    def padding(self) -> bytearray:
        return self._padding
    
    @padding.setter
    def padding(self, value: bytearray):
        self.padding = value[0:8].copy()

    def as_bytearray(self):
        returnByteArray = super().as_bytearray()
        returnByteArray = returnByteArray[-12:]
        returnByteArray.extend(self.key_pair_address.copy())
        returnByteArray.extend(self.padding.copy())
        return returnByteArray
    
#TODO: start here with figure 5 on page 13


class SLH_DSA:
    def __init__(self):
        pass
    
    # algorithm 1
    def gen_len_2(self, n: int, lg_w: int):
        # as stated in the document, all parameter sets have len2 = 3
        # so I'm not going to bother calculating this
        return 3

    #algorithm 2
    def toInt(self, X: bytearray, n: int):
        return int.from_bytes(X, "big")

    #algorithm 3
    def toInt(self, x: int, n: int):
        return x.to_bytes(n, "big")
    
    #algorithm 4
    # I'm modifying their version which uses a lot of shifts which is unnecessary.
    # They should have expected a 64-byte register.
    def base_2b(X: bytearray, b: int, out_len: int):
        baseb = array("I")
        i = 0
        for out in range(0, out_len):
            bits = 0
            total = 0
            while (bits < b):
                total = (total << 8) + X[i]
                i = i + 1
                bits = bits + 8
            shiftRight = bits - b
            baseb.append((total >> shiftRight) % 2**b)
        return baseb


    
    # table member functions (on page 14)

    # WOTS algorithms on page 17
    

# on page 44
def H_msg():
    pass

def PRF():
    pass

def PRF_msg():
    pass

def F():
    pass

def H():
    pass

def T_l():
    pass