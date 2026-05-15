from array import array
from abc import ABC, abstractmethod
from enum import Enum
from math import ceil
import os

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


class SLH_DSA_SK:
    def __init__(self, n: int):
        self._n = n
        self.SK_seed = bytearray([0] * n)
        self.SK_prf = bytearray([0] * n)
        self.PK_seed = bytearray([0] * n)
        self.PK_root = bytearray([0] * n)
    
    @property
    def SK_seed(self) -> bytearray:
        return self._SK_seed
    
    @SK_seed.setter
    def SK_seed(self, value: bytearray):
        self.SK_seed = value[0:self._n]

    @property
    def SK_prf(self) -> bytearray:
        return self._SK_prf
    
    @SK_prf.setter
    def SK_prf(self, value: bytearray):
        self.SK_prf = value[0:self._n]

    @property
    def PK_seed(self) -> bytearray:
        return self._PK_seed
    
    @PK_seed.setter
    def PK_seed(self, value: bytearray):
        self.PK_seed = value[0:self._n]

    @property
    def PK_root(self) -> bytearray:
        return self._PK_root
    
    @PK_root.setter
    def PK_root(self, value: bytearray):
        self.PK_root = value[0:self._n]

class SLH_DSA_PK:
    def __init__(self, n: int):
        self._n = n
        self.PK_seed = bytearray([0] * n)
        self.PK_root = bytearray([0] * n)
    
    @property
    def PK_seed(self) -> bytearray:
        return self._PK_seed
    
    @PK_seed.setter
    def PK_seed(self, value: bytearray):
        self.PK_seed = value[0:self._n]

    @property
    def PK_root(self) -> bytearray:
        return self._PK_root
    
    @PK_root.setter
    def PK_root(self, value: bytearray):
        self.PK_root = value[0:self._n]



class SLH_DSA(ABC):
    def __init__(self):
        self.n = 0 # TODO: actually set with parameters
        self.h_prime = 0 #TODO: actually set with parameters
        self.d = 0 #TODO: actually set with parameters
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
    
    # algorithm 8
    def wots_pkFromSig(self, sig: bytearray, M: bytearray, PK_seed: bytearray, ADRS: Address):
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

        #8 - 11
        temp = bytearray()
        for i in range(0, self.len):
            ADRS.setChainAddress(i)
            temp.extend(self.chain(sig[i], msg[i], self.w-1-msg[i] , PK_seed, ADRS.as_bytearray()))

        #12 - 14 (taken care of in __init__)
        wotspkADRS = WOTS_PK_Address(ADRS.as_bytearray())

        pk_sig = self.T_len(PK_seed, wotspkADRS, temp)
        return pk_sig
    
    # algorithm 9
    def xmss_node(self, SK_seed: bytearray, i: int, z: int, PK_seed: bytearray, ADRS: Address) -> bytearray:
        node = bytearray()
        if (z == 0):
            WotsHashADRS = WOTS_Hash_Address(ADRS)
            WotsHashADRS.setKeyPairAddress(i)
            node = self.wots_pkGen(SK_seed, PK_seed, WotsHashADRS)
        else:
            # recursion
            lnode = self.xmss_node(SK_seed, 2*i, z - 1, PK_seed, ADRS)
            rnode = self.xmss_node(SK_seed, 2*i + 1, z - 1, PK_seed, ADRS)
            TreeADRS = Hash_Tree_Address(ADRS.as_bytearray())
            TreeADRS.setTreeHeight(z)
            TreeADRS.setTreeIndex(i)

            # 11
            temp = lnode.copy()
            temp.extend(rnode)
            node = self.H(PK_seed, TreeADRS, temp)
        return node
    
    # Algorithm 10
    def xmss_sign(self, M: bytearray, SK_seed: bytearray, idx: int, PK_seed: bytearray, ADRS: Address) -> bytearray:
        AUTH = bytearray()
        for j in range(0, self.h_prime):
            k = (idx >> j) ^ 0x01
            AUTH.extend(self.xmss_node(SK_seed, k, j, PK_seed, ADRS))
        
        wotsHash = WOTS_Hash_Address(ADRS.as_bytearray())
        wotsHash.setKeyPairAddress(idx)
        sig = self.wots_sign(M, SK_seed, PK_seed, wotsHash)
        sig.extend(AUTH)
        return sig
    
    # Algorithm 11
    def xmss_pkFromSig(self, idx: int, SIG_xmss: bytearray, M: bytearray, PK_seed: bytearray, ADRS: Address) -> bytearray:
        wotsHash = WOTS_Hash_Address(ADRS.as_bytearray())
        wotsHash.setKeyPairAddress(idx)

        sig = SIG_xmss[0:(self.len * self.n)].copy()
        AUTH = SIG_xmss[(self.len * self.n):((self.len + self.h_prime) * self.n)].copy()

        node_0 = self.wots_pkFromSig(sig, M, PK_seed, wotsHash)

        TreeADRS = Hash_Tree_Address(wotsHash.as_bytearray())
        TreeADRS.setTypeAndClear(TreeType.TREE.value)
        TreeADRS.setTreeIndex(idx)

        for k in range(0, self.h_prime):
            TreeADRS.setTreeHeight(k + 1)
            if ((idx >> k) % 2 == 0):
                TreeADRS.setTreeIndex(TreeADRS.getTreeIndex() // 2) #TODO: replace with shift
                temp = node_0.copy()
                temp.extend(AUTH[(k*self.n):((k + 1) * self.n)])
                node_1 = self.H(PK_seed, TreeADRS, temp)
            else:
                TreeADRS.setTreeIndex((TreeADRS.getTreeIndex() - 1)// 2) # todo: relplace with shift
                temp = AUTH[(k*self.n):((k + 1) * self.n)].copy()
                temp.extend(node_0)
                node_1 = self.H(PK_seed, TreeADRS, temp)
            node_0 = node_1.copy()
        return node_0
    
    # algorithm 12
    def ht_sign(self, M: bytearray, SK_seed: bytearray, PK_seed: bytearray, idx_tree: int, idx_leaf: int) -> bytearray:
        ADRS = Address([0] * 32)
        ADRS.setTreeAddress(idx_tree)

        SIG_temp = self.xmss_sign(M, SK_seed, idx_leaf, PK_seed, ADRS)
        SIG_ht = SIG_temp.copy()
        root = self.xmss_pkFromSig(idx_leaf, SIG_temp, M, PK_seed, ADRS)
        for j in range(1, self.d):
            idx_leaf = idx_tree % 2**self.h_prime
            idx_tree = idx_tree >> self.h_prime
            ADRS.setLayerAddress(j)
            ADRS.setTreeAddress(idx_tree)
            SIG_temp = self.xmss_sign(root, SK_seed, idx_leaf, PK_seed, ADRS)
            SIG_ht.extend(SIG_temp)
            if (j < self.d - 1):
                root = self.xmss_pkFromSig(idx_leaf, SIG_temp, root, PK_seed, ADRS)
        return SIG_ht

    #Algorithm 13
    def ht_verify(self, M: bytearray, SIG_ht: bytearray, PK_seed: bytearray, idx_tree: int, idx_leaf: int, PK_root: bytearray) -> bytearray:
        ADRS = Address([0] * 32)
        ADRS.setTreeAddress(idx_tree)
        SIG_tmp = SIG_ht[0:((self.h_prime + self.len) * self.n)].copy()
        node = self.xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK_seed, ADRS)
        for j in range(1, self.d):
            idx_leaf = idx_tree % 2**self.h_prime
            idx_tree = idx_tree >> self.h_prime
            ADRS.setLayerAddress(j)
            ADRS.setTreeAddress(idx_tree)
            SIG_tmp = SIG_ht[(j * (self.h_prime + self.len) * self.n):((j + 1) * (self.h_prime + self.len) * self.n)].copy()
            node = self.xmss_pkFromSig(idx_leaf, SIG_tmp, node, PK_seed, ADRS)
        return PK_root == node

    # FORS
    #Algorithm 14
    def fors_skGen(self, SK_seed: bytearray, PK_seed: bytearray, ADRS: Address, idx: int) -> bytearray:
        skADRS = FORS_PRF_Address(ADRS.as_bytearray())
        skADRS.setTypeAndClear(TreeType.FORS_PRF.value)
        skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        skADRS.setTreeIndex(idx)
        return self.PRF(PK_seed, SK_seed, skADRS)
    
    # Algorithm 15
    def fors_node(self, SK_seed: bytearray, i: int, z: int, PK_seed: bytearray, ADRS: Address) -> bytearray:
        if (z == 0):
            sk = self.fors_skGen(SK_seed, PK_seed, ADRS, i)
            ADRS.setTreeHeight(0)
            ADRS.setTreeIndex(i)
            node = self.F(PK_seed, ADRS, sk)
        else:
            # recursion
            lnode = self.fors_node(SK_seed, 2*i, z - 1, PK_seed, ADRS)
            rnode = self.fors_node(SK_seed, 2*i + 1, z - 1, PK_seed, ADRS)
            TreeADRS = Hash_Tree_Address(ADRS.as_bytearray())
            TreeADRS.setTreeHeight(z)
            TreeADRS.setTreeIndex(i)

            # 11
            temp = lnode.copy()
            temp.extend(rnode)
            node = self.H(PK_seed, TreeADRS, temp)
        return node


    # Algorithm 16
    def fors_sign(self, md: bytearray, SK_seed: bytearray, PK_seed: bytearray, ADRS: Address) -> bytearray:
        SIG_fors = bytearray()
        indices = self.base_2b(md, self.a, self.k)
        for i in range(0, self.k):
            SIG_fors.extend(self.fors_skGen(SK_seed, PK_seed, ADRS, (i << self.a) + indices[i]))
            AUTH = bytearray()
            for j in range(0, self.a):
                s = (indices[i] >> j) ^ 0x01
                AUTH.extend(self.fors_node(SK_seed, (i << (self.a - j) + s), j, PK_seed, ADRS))
            SIG_fors.extend(AUTH)
        return SIG_fors
    
    # Algorithm 17
    def fors_pkFromSig(self, SIG_fors: bytearray, md: bytearray, PK_seed: bytearray, ADRS: Address) -> bytearray:
        root = bytearray()
        indices = self.base_2b(md, self.a, self.k)
        for i in range(0, self.k):
            sk_start = i * (self.a + 1) * self.n
            sk_end = (i * (self.a + 1) + 1) * self.n
            sk = SIG_fors[sk_start:sk_end].copy()
            ADRS.setTreeHeight(0)
            ADRS.setTreeIndex(i << self.a + indices[i])
            node_0 = self.F(PK_seed, ADRS, sk)

            sig_start = sk_end
            sig_end = (((i + 1) * (self.a + 1) + 1)* self.n)
            AUTH = SIG_fors[sig_start:sig_end].copy() 
            for j in range(0, self.a):
                ADRS.setTreeHeight(j + 1)
                if ((indices[i] >> j) % 2 == 0):
                    ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
                    temp = node_0.copy()
                    temp.extend(AUTH[(j * self.n):((j + 1) * self.n)])
                    node_1 = self.H(PK_seed, ADRS, temp)
                else:
                    ADRS.setTreeIndex((ADRS.getTreeIndex() -1) // 2)
                    temp = AUTH[(j * self.n):((j + 1) * self.n)].copy()
                    temp.extend(node_0)
                    node_1 = self.H(PK_seed, ADRS, temp)
                node_0 = node_1.copy()
            root.extend(node_0)
        forspkADRS = FORS_Tree_Roots_Address(ADRS.as_bytearray())
        forspkADRS.setTypeAndClear(TreeType.FORS_ROOTS)
        forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
        pk = self.T_len(PK_seed, forspkADRS, root) #todo: len?


    #Algorithm 18
    def slh_keygen_internal(self, SK_seed: bytearray, SK_prf: bytearray, PK_seed: bytearray) -> tuple[SLH_DSA_SK, SLH_DSA_PK]:
        ADRS = Address()
        ADRS.setLayerAddress(self.d - 1)
        PK_root = self.xmss_node(SK_seed, 0, self.h_prime, PK_seed, ADRS)

        sk = SLH_DSA_SK(self.n)
        sk.PK_root = PK_root
        sk.PK_seed = PK_seed
        sk.SK_prf = SK_prf
        sk.SK_seed = SK_seed

        pk = SLH_DSA_PK(self.n)
        pk.PK_root = PK_root
        pk.PK_seed = PK_seed

        return sk, pk

    # Algorithm 19
    #TODO: deterministic variant
    def slh_sign_internal(self, M: bytearray, SK: SLH_DSA_SK, addrnd: bytearray) -> bytearray:
        ADRS = Address()

        opt_rand = addrnd.copy()
        R : bytearray = self.PRF_msg(SK.SK_prf, opt_rand, M) 
        sig = R.copy()

        digest = self.H_msg(R, SK.PK_seed, SK.PK_root, M) # digest the message based upon the PK seed and root

        # temporary values
        k_a_8 = ceil(self.k * self.a / 8)
        h_h_d = ceil(self.h - (self.h / self.d) / 8)
        h_8_d = ceil(self.h / (self.d * 8))

        md = digest[0:k_a_8] # first bytes are the digest
        tmp_idx_tree = digest[k_a_8:(k_a_8 + h_h_d)] # next bytes are the index of the tree to be used to sign the message
        tmp_idx_leaf = digest[(k_a_8 + h_h_d):(k_a_8 + h_h_d + h_8_d)] #next bytes are the index of the leaf to be used

        # 9-10
        # convert those byte address to ints now

        idx_tree = SLH_DSA.toInt(tmp_idx_tree, h_h_d) % 2**(self.h - (self.h // self.d))
        idx_leaf = SLH_DSA.toInt(tmp_idx_leaf, h_8_d) % 2**(self.h // self.d)

        #11 - 13
        forsADRS = FORS_Tree_Address(ADRS.as_bytearray())
        forsADRS.setTreeAddress(idx_tree)
        forsADRS.setTypeAndClear(TreeType.FORS_TREE.value)
        forsADRS.setKeyPairAddress(idx_leaf)

        #14
        SIG_fors = self.fors_sign(md, SK.SK_seed, SK.PK_seed, forsADRS)

        #15
        sig.extend(SIG_fors)

        #16
        PK_fors = self.fors_pkFromSig(SIG_fors, md, SK.PK_seed, forsADRS)

        #17
        SIG_ht = self.ht_sign(PK_fors, SK.SK_seed, SK.PK_seed, forsADRS)

        #18
        sig.extend(SIG_ht)

        #19
        return sig

    #Algorithm 20
    def slh_verify_internal(self, M: bytearray, SIG: bytearray, PK: SLH_DSA_PK) -> bool:
        if (len(SIG) != (1 + self.k * (1 + self.a) + self.h + self.d * self.len) * self.n):
            return False
        
        ADRS = Address()
        R = SIG[0:self.n].copy()

        SIG_fors = SIG[self.n:((1 + self.k * (self.a + 1)) * self.n)]
        SIG_ht = SIG[((1 + self.k * (self.a + 1)) * self.n):((1 + self.k * (self.a + 1) + self.h + self.d * self.len) * self.n)]

        digest = self.H_msg(R, PK.PK_seed, PK.PK_root, M)

        # temporary values
        k_a_8 = ceil(self.k * self.a / 8)
        h_h_d = ceil(self.h - (self.h / self.d) / 8)
        h_8_d = ceil(self.h / (self.d * 8))

        md = digest[0:k_a_8] # first bytes are the digest
        tmp_idx_tree = digest[k_a_8:(k_a_8 + h_h_d)] # next bytes are the index of the tree to be used to sign the message
        tmp_idx_leaf = digest[(k_a_8 + h_h_d):(k_a_8 + h_h_d + h_8_d)] #next bytes are the index of the leaf to be used

        # 9-10
        # convert those byte address to ints now

        idx_tree = SLH_DSA.toInt(tmp_idx_tree, h_h_d) % 2**(self.h - (self.h // self.d))
        idx_leaf = SLH_DSA.toInt(tmp_idx_leaf, h_8_d) % 2**(self.h // self.d)

        #11 - 13
        forsADRS = FORS_Tree_Address(ADRS.as_bytearray())
        forsADRS.setTreeAddress(idx_tree)
        forsADRS.setTypeAndClear(TreeType.FORS_TREE.value)
        forsADRS.setKeyPairAddress(idx_leaf)


        #16
        PK_fors = self.fors_pkFromSig(SIG_fors, md, PK.PK_seed, forsADRS)

        return self.ht_verify(PK_fors, SIG_ht, PK.PK_seed, idx_tree, idx_leaf, PK.PK_root)

    # Algorithm 21

    def slh_keygen(self) -> tuple[SLH_DSA_SK, SLH_DSA_PK]:
        SK_seed = bytearray(os.urandom(self.n))
        SK_prf = bytearray(os.urandom(self.n))
        PK_seed = bytearray(os.urandom(self.n))

        if (SK_seed == None) or (PK_seed == None) or (SK_prf == None):
            return None, None
        
        return self.slh_keygen_internal(SK_seed, SK_prf, PK_seed)


    #TODO: create algorithm 22






    
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
    
