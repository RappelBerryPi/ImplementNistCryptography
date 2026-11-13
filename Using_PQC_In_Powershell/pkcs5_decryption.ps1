$password = "abc.txt"
<#
-----BEGIN PRIVATE KEY-----
MFQCAQAwCwYJYIZIAWUDBAQDBEKAQCU0fCayZmnMoX9gcUuguvejnxO/bui3VYfL
0o38XEM5ppCudUQz8pKMEqKwGQQTPbv67rEcI2SQmeNps9kdK6g=
-----END PRIVATE KEY-----
#>

$encryptedKeyValue = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHEMGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBBH3KN5hhjTSuZxG/b0
8Cn4AgMBhqAwDAYIKoZIhvcNAgsFADAdBglghkgBZQMEASoEEF1P60SCx9Pjolku
+cyT5OQEYN3ePjsHCnZdRbG5IH5OASBmClOkqja2hRCvuc8Ktwr7dDK3Hkq6VJy8
Jn3t5qUyV8SalmeQuO8VmAuTP7LOiBe3EnPFnG4ob7/u8v9Mn8oRnFJBeMxu9Bhq
HYZKILf8NA==
-----END ENCRYPTED PRIVATE KEY-----"

$encryptedKeyValue = $encryptedKeyValue.Replace("-----BEGIN ENCRYPTED PRIVATE KEY-----","")
$encryptedKeyValue = $encryptedKeyValue.Replace("-----END ENCRYPTED PRIVATE KEY-----","")

$bytes = [System.Convert]::FromBase64String($encryptedKeyValue)
$data = [System.ReadOnlyMemory[byte]]::new($bytes)

$asn1Reader = [System.Formats.Asn1.AsnReader]::new($data, [System.Formats.Asn1.AsnEncodingRules]::DER)

$asn1Reader = $asn1Reader.ReadSequence()

$inner = $asn1Reader.ReadSequence()

$encryptedData = $asn1Reader.ReadOctetString() # byte array

if (-not ($asn1Reader.HasData -eq $false)) {
    throw "InvalidState"
}

$objIdentifier = $inner.ReadObjectIdentifier() # 1.2.840.113549.1.5.13 == pkcs5PBES2

$inner2 = $inner.ReadSequence()

if (-not ($inner.HasData -eq $false)) {
    throw "InvalidState"
}

$inner3 = $inner2.ReadSequence()

$inner4 = $inner2.ReadSequence()


if (-not ($inner2.HasData -eq $false)) {
    throw "InvalidState"
}

$objIdentifier2 = $inner3.readObjectIdentifier() # 1.2.840.113549.1.5.12 = pkcs5PBKDF2

$inner5 = $inner3.ReadSequence()

if (-not ($inner3.HasData -eq $false)) {
    throw "InvalidState"
}

$salt = $inner5.ReadOctetString()
$count = $inner5.ReadInteger()
$inner6 = $inner5.ReadSequence()

if (-not ($inner5.HasData -eq $false)) {
    throw "InvalidState"
}

$objIdentifier3 = $inner6.readObjectIdentifier() # 1.2.840.113549.2.11 = HmacWithSha512 hash funnction used in pbkdf2
$inner6.ReadNull()

if (-not ($inner6.HasData -eq $false)) {
    throw "InvalidState"
}

$objIdentifier4 = $inner4.ReadObjectIdentifier() # 2.16.840.1.101.3.4.1.42 = aes256-cbc
$IV = $inner4.ReadOctetString()

# $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $octetString2, $count).GetBytes(32)
$key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, $count, [System.Security.Cryptography.HashAlgorithmName]::SHA512).GetBytes(32)

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $IV
$aes.Mode= [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$decryptor = $aes.CreateDecryptor()
$memoryStream = [System.IO.MemoryStream]::new($encryptedData)
$cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

$decryptedKey = [System.Byte[]]::new($encryptedData.Length)

$cryptoStream.Read($decryptedKey,0, $encryptedData.Length) | Out-Null
while ($decryptedKey[-1] -eq 0) {
    $decryptedKey = $decryptedKey[0..($decryptedKey.Length - 2)]
}
$decryptedKey # this is now a private key info and from here we can get whatever value


# $decryptedKey
# $decryptedKey0_start = 