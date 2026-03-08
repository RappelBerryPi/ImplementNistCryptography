# Steps

1. run certutil

```{PowerSHell}
certutil -key -user
```

2. "Microsoft Strong Cryptographic Provider:
  f6b5f7ef-9774-48bb-812b-f6944b6bd675
  062f15f8f98288e162105ae709a21d3d_14ef52e5-8bdd-473c-b844-54c1ee27ca60
  RSA
    AT_SIGNATURE"

3. go to 'C:\Users\[username]\AppData\Roaming\Microsoft\Crypto\RSA\[userSID]'

4. cat out '062f15f8f98288e162105ae709a21d3d_14ef52e5-8bdd-473c-b844-54c1ee27ca60'

5. `[System.io.FIle]::ReadAllBytes([filepath])`

6. bytes 0 - 40????
7. Bytes 40-75
   1. `[System.Text.Encoding]::UTF8.GetString($b[40..75])`
   2. f6b5f7ef-9774-48bb-812b-f6944b6bd675
   3. notice the match to what was listed above
8. Bytes 76 - 96 ????
   1. all zeros, why?
9. Bytes 97-100
    1. `[System.Text.Encoding]::UTF8.GetString($b[97..100])`
    2. RSA1 <- meaning that this is a public key
    3. https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey or https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob?
10. bit len (101 - 104)
    1. $b[101..104]
    2. 136,0,0,0
    3. [System.BitConverter]::ToUInt32($b[101..104], 0)
    4. 136?
11. bytes exponent len
    3. $b[105..108]
    4. 0, 4, 0, 0
    3. [System.BitConverter]::ToUInt32($b[105..108], 0)
    4. 1024 (bytes?)
12. modulus len?
    1. $b[109..112]
    3. [System.BitConverter]::ToUInt32($b[109..112], 0)
    5. 127 (bytes?)
13. public exponent
    1. $b[113..116]
    3. [System.BitConverter]::ToUInt32($b[113..116], 0)
    4. 65537
14. modulus?
    1. $b[117..243]
15. prime1?
    1. $b[243] + exponent length / 2
    2. $b[243..754]
16. prime2?
    2. $b[755..1266]


1279 bytes.... hmmm

13.


none of this is really matching up..... not sure what's going on here...