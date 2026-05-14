from array import array
from abc import ABC, abstractmethod
from enum import Enum
from math import ceil

class TreeType(Enum):
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4
    WOTS_PRF = 5
    FORS_PRF = 6


# addresses as described on page 11 -14
class Address(ABC):
    def __init__(self):
        self.bytes = bytearray([0] * 32)

    def __init__(self, bytes: bytearray):
        self.bytes = bytes[0:32]
    
    @property
    def layer_address(self) -> bytearray:
        return self.bytes[0:4].copy()
    
    @layer_address.setter
    def layer_address(self, value: bytearray):
        self.bytes[0:4] = value[0:4]
    
    @property
    def tree_address(self) -> bytearray:
        return self.bytes[4:16].copy()
    
    @tree_address.setter
    def tree_address(self, value: bytearray):
        self.bytes[4:16] = value[0:12]
    
    @property
    def address_type(self) -> bytearray:
        return self.bytes[16:20].copy()
    
    @address_type.setter
    def address_type(self, value: bytearray):
        self.bytes[16:20] = value[0:4]
    
    def as_bytearray(self):
        return self.bytes.copy()
    
    # member functions in section 4.3

    def setLayerAddress(self, l: int):
        self.layer_address = SLH_DSA.toByte(l, 4)

    def setTreeAddress(self, t: int):
        self.tree_address = SLH_DSA.toByte(t, 12)
    
    def setTypeAndClear(self, Y: int):
        self.address_type = SLH_DSA.toByte(Y, 4)
        self.bytes[20:32] = bytearray([0] * 12)
    
    def setKeyPairAddress(self, i: int):
        self.bytes[20:24] = SLH_DSA.toByte(i, 4)

    def setChainAddress(self, i: int):
        self.bytes[24:28] = SLH_DSA.toByte(i, 4)

    def setTreeHeight(self, i: int):
        self.bytes[24:28] = SLH_DSA.toByte(i, 4)

    def setHashAddress(self, i: int):
        self.bytes[28:32] = SLH_DSA.toByte(i, 4)

    def setTreeIndex(self, i: int):
        self.bytes[28:32] = SLH_DSA.toByte(i, 4)
    
    def getKeyPairAddress(self) -> int:
        return SLH_DSA.toInt(self.bytes[20:24], 4)

    def getTreeIndex(self) -> int:
        return SLH_DSA.toInt(self.bytes[28:32], 4)

class WOTS_Hash_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 0])
    
    def __init__(self, bytes: bytearray):
        super().__init__(bytes)
        self.address_type = bytearray([0, 0, 0, 0])
    
    @property
    def key_pair_address(self) -> bytearray:
        return self.bytes[20:24].copy()
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.bytes[20:24] = value[0:4]
    
    @property
    def chain_address(self) -> bytearray:
        return self.bytes[24:28].copy()
    
    @chain_address.setter
    def chain_address(self, value: bytearray):
        self.bytes[24:28] = value[0:4]

    @property
    def hash_address(self) -> bytearray:
        return self.bytes[28:32].copy()

    @hash_address.setter
    def hash_address(self, value: bytearray):
        self.bytes[28:32] = value[0:4]

class WOTS_PK_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 1])

    def __init__(self, bytes: bytearray):
        super().__init__(bytes)
        self.address_type = bytearray([0, 0, 0, 1])

    @property
    def key_pair_address(self) -> bytearray:
        return self.bytes[20:24].copy()
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.bytes[20:24] = value[0:4]

    @property
    def padding(self) -> bytearray:
        return self.bytes[24:32].copy()
    
    @padding.setter
    def padding(self, value: bytearray):
        self.bytes[24:32] = value[0:8]

class Hash_Tree_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 2])

    def __init__(self, bytes):
        super().__init__(bytes)
        self.address_type = bytearray([0, 0, 0, 2])

    @property
    def padding(self) -> bytearray:
        return self.bytes[20:24].copy()
    
    @padding.setter
    def padding(self, value: bytearray):
        self.bytes[20:24] = value[0:4]
    
    @property
    def tree_height(self) -> bytearray:
        return self.bytes[24:28].copy()
    
    @tree_height.setter
    def tree_height(self, value: bytearray):
        self.bytes[24:28] = value[0:4]

    @property
    def tree_index(self) -> bytearray:
        return self.bytes[28:32].copy()

    @tree_index.setter
    def tree_index(self, value: bytearray):
        self.bytes[28:32] = value[0:4]

class FORS_Tree_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 3])
        self.layer_address = bytearray([0, 0, 0, 0])

    def __init__(self, bytes):
        super().__init__(bytes)
        self.address_type = bytearray([0, 0, 0, 3])
        self.layer_address = bytearray([0, 0, 0, 0])

    @property
    def key_pair_address(self) -> bytearray:
        return self.bytes[20:24].copy()
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.bytes[20:24] = value[0:4]
    
    @property
    def tree_height(self) -> bytearray:
        return self.bytes[24:28].copy()
    
    @tree_height.setter
    def tree_height(self, value: bytearray):
        self.bytes[24:28] = value[0:4]

    @property
    def tree_index(self) -> bytearray:
        return self.bytes[28:32].copy()

    @tree_index.setter
    def tree_index(self, value: bytearray):
        self.bytes[28:32] = value[0:4]

class FORS_Tree_Roots_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 4])
        self.layer_address = bytearray([0, 0, 0, 0])
        self.padding = bytearray([0, 0, 0, 0, 0, 0, 0, 0])

    def __init__(self, bytes):
        super().__init__(bytes)
        self.address_type = bytearray([0, 0, 0, 4])
        self.layer_address = bytearray([0, 0, 0, 0])
        self.padding = bytearray([0, 0, 0, 0, 0, 0, 0, 0])

    @property
    def key_pair_address(self) -> bytearray:
        return self.bytes[20:24].copy()
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.bytes[20:24] = value[0:4]
    
    @property
    def padding(self) -> bytearray:
        return self.bytes[24:32].copy()

    @padding.setter
    def padding(self, value: bytearray):
        self.bytes[24:32] = value[0:8]

class WOTS_PRF_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 5])
        self.hash_address = bytearray([0, 0, 0, 0])

    def __init__(self, bytes):
        super().__init__(bytes)
        self.address_type = bytearray([0, 0, 0, 5])
        self.hash_address = bytearray([0, 0, 0, 0])

    @property
    def key_pair_address(self) -> bytearray:
        return self.bytes[20:24].copy()
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.bytes[20:24] = value[0:4]
    
    @property
    def chain_address(self) -> bytearray:
        return self.bytes[24:28].copy()
    
    @chain_address.setter
    def chain_address(self, value: bytearray):
        self.bytes[24:28] = value[0:4]

    @property
    def hash_address(self) -> bytearray:
        return self.bytes[28:32].copy()

    @hash_address.setter
    def hash_address(self, value: bytearray):
        self.bytes[28:32] = value[0:4]

class FORS_PRF_Address(Address):
    def __init__(self):
        super().__init__()
        self.address_type = bytearray([0, 0, 0, 6])
        self.tree_height = bytearray([0, 0, 0, 0])

    def __init__(self, bytes):
        super().__init__(bytes)
        self.address_type = bytearray([0, 0, 0, 6])
        self.tree_height = bytearray([0, 0, 0, 0])

    @property
    def key_pair_address(self) -> bytearray:
        return self.bytes[20:24].copy()
    
    @key_pair_address.setter
    def key_pair_address(self, value: bytearray):
        self.bytes[20:24] = value[0:4]
    
    @property
    def tree_height(self) -> bytearray:
        return self.bytes[24:28].copy()
    
    @tree_height.setter
    def tree_height(self, value: bytearray):
        self.bytes[24:28] = value[0:4]

    @property
    def tree_index(self) -> bytearray:
        return self.bytes[28:32].copy()

    @tree_index.setter
    def tree_index(self, value: bytearray):
        self.bytes[28:32] = value[0:4]




class SLH_DSA(ABC):
    def __init__(self):
        self.n = 0 # TODO: actually set with parameters
        self.lg_w = 4
        self.w = 16
        self.len_1 = 2 * self.n
        self.len_2 = 3
        self.len = 2 * self.n + 3
        pass
    
    # algorithm 1
    def gen_len_2(self, n: int, lg_w: int):
        # as stated in the document, all parameter sets have len2 = 3
        # so I'm not going to bother calculating this
        return 3

    #algorithm 2
    def toInt(X: bytearray, n: int):
        return int.from_bytes(X, "big")

    #algorithm 3
    def toByte(x: int, n: int):
        return x.to_bytes(n, "big")
    
    #algorithm 4
    # I'm modifying their version which uses a lot of shifts which is unnecessary.
    # They should have expected a 64-byte register.
    def base_2b(self, X: bytearray, b: int, out_len: int):
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

    # algorithm 5
    def chain(self, X: bytearray, i: int, s: int, pk_seed: bytearray, ADRS: Address) -> bytearray:
        temp = X.copy()
        for j in range(i, i + s):
            ADRS.setHashAddress(j)
            temp = self.F(pk_seed, ADRS.as_bytearray(), temp)
        return temp
    
    # algorithm 6
    def wots_pkGen(self, SK_seed: bytearray, PK_seed: bytearray, ADRS: Address):
        # 1 - 3 taken care of in WOTS_PRF_Address creation
        skADRS = WOTS_PRF_Address(ADRS.as_bytearray())

        #4 - 9
        temp = bytearray()
        for i in range(0, self.len):
            skADRS.setChainAddress(i)
            sk = self.PRF(PK_seed, SK_seed, skADRS.as_bytearray())
            ADRS.setChainAddress(i)
            temp.extend(self.chain(sk, 0, self.w - 1, PK_seed, ADRS.as_bytearray()))
        
        #10 - 12
        wotspkADRS = WOTS_PK_Address(ADRS.as_bytearray())

        #13
        pk = self.T_len(PK_seed, wotspkADRS.as_bytearray(), temp)
        return pk
    
    # algorithm 7
    def wots_sign(self, M: bytearray, SK_seed: bytearray, PK_seed: bytearray, ADRS: Address):
        #1
        csum = 0

        #2
        msg = self.base_2b(M, self.lg_w, self.len_1)

        #3 - 5
        for i in range(0, self.len_1):
            csum = csum + self.w - 1 - msg[i]

        #6
        csum = csum << ((8 - ((self.len_2 * self.lg_w) % 8)) % 8)

        #7
        byteSize = ceil(self.len_2 * self.lg_w / 8)
        msg.extend(self.base_2b(SLH_DSA.toByte(csum, byteSize), self.lg_w, self.len_2))

        #8 - 10
        skADRS = WOTS_PRF_Address(ADRS.as_bytearray())

        #11-15
        sig = bytearray()
        for i in range(0, self.len):
            skADRS.setChainAddress(i)
            sk = self.PRF(PK_seed, SK_seed, skADRS.as_bytearray())
            ADRS.setChainAddress(i)
            sig.extend(self.chain(sk, 0, msg[i], PK_seed, ADRS.as_bytearray()))
        return sig
    
    # TODO: start here and work on Algorithm 8
    
    # on page 44
    # what the following are depends on what the parameter set is. SHAKE parameter sets use SHAKE256, SHA-2 Parameter sets use
    # SHA-2. WE're going to have to have a derived class
    #TODO: create derived SLH_DSA_SHA2 and SLH_DSA_SHAKE that override this plus the other functions in section 11.1 and
    #11.2

    @abstractmethod
    def H_msg(self, R: bytearray, PK_seed: bytearray, PK_root: bytearray, M: bytearray) -> bytearray:
        pass

    @abstractmethod
    def PRF(self, PK_seed: bytearray, SK_seed: bytearray, ADRS: bytearray) -> bytearray:
        pass

    @abstractmethod
    def PRF_msg(SK_prf: bytearray, opt_rand: bytearray, M: bytearray) -> bytearray:
        pass

    @abstractmethod
    def F(self, PK_seed: bytearray, ADRS: bytearray, M: bytearray) -> bytearray:
        pass

    @abstractmethod
    def H(self, PK_seed: bytearray, ADRS: bytearray, M: bytearray) -> bytearray:
        pass

    @abstractmethod
    def T_len(self, PK_seed: bytearray, ADRS: bytearray, M: bytearray) -> bytearray:
        pass

    
    # WOTS algorithms on page 17
    
