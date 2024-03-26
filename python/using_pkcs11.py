import pkcs11

lib = pkcs11.lib("E:\\SoftHSM2\\lib\\softhsm2-x64.dll")
token = lib.getToken(token_label="")

with token.open(user_pin="1234") as session:
    pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 2048)
    print(priv)
    print(priv.sign("abcd"))