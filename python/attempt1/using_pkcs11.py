is_python_pkcs11 = False

try:
    import pkcs11
    is_python_pkcs11 = True
except ModuleNotFoundError:
    from PyKCS11 import PyKCS11

# soft_hsm = "E:\\SoftHSM2\\lib\\softhsm2-x64.dll"
soft_hsm = r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"
if (is_python_pkcs11):
    lib = pkcs11.lib(soft_hsm)
    token = lib.getToken(token_label="")

    with token.open(user_pin="1234") as session:
        pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 2048)
        print(priv)
        print(priv.sign("abcd"))
else:
    lib = PyKCS11.PyKCS11Lib()
    lib.load(soft_hsm)
    slot = lib.getSlotList(tokenPresent=True)[0]
    session = lib.openSession(slot)
    session.login('07254096')
    session.findObjects()
    symKey = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
    text = str(symKey)
    session.decrypt()
    print(text)


# test for wrapping and unwrapping. create an object with the appropriate things and make it abstract for python-pkcs11
# and pykcs11
# https://github.com/LudovicRousseau/PyKCS11/blob/master/test/test_wrap.py
