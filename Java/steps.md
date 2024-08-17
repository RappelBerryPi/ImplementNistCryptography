# steps to repeat

NOTE: do NOT use SoftHSM as your PKCS11 provider.
It will work (technically) but it's not an HSM.
It shows that the keys are non extractable and shows good programming practices.
However, the use of SoftHSM for anything other than prototyping is a VERY bad idea.
when you are done prototyping, use a REAL HSM (FIPS 140-2 Level 2 or above).

1. Install softHSM
2. Run `softhsm2-util`
3. Create config file
4. run keytool to create the key

```bash
keytool -genkeypair -alias RSAKEY1 -keyalg RSA -keysize 4096 -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg softHSM.cfg
```

5. list the keys

```bash
keytool -list -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg softHSM.cfg
```

6. Load the keystore through a specific java call. (see UsingPKCS11.java)

7. running the example code will translate the calls to a PKCS11 call and will show that the key
   is not extractable and if you call privateKey.getEncoded() you get no value because the key is not in memory.

```bash
$ java UsingPkcs11.java 1234
SunPKCS11-SoftHSM RSA private key, 4096 bitstoken object, not sensitive, unextractable)
null
[B@6adbc9d
```

## note

A full list of PKCS11 supported algorithms in the Sun PKCS11 provider are listed below:
https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-D3EF9023-7DDC-435D-9186-D2FD05674777
