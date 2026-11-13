#foreach
# Get-ChildItem "C:\Users\${env:USERNAME}\AppData\Roaming\Microsoft\Crypto\Keys"

$bytes = Get-Content -Encoding Byte "C:\Users\${env:USERNAME}\AppData\Roaming\Microsoft\Crypto\Keys\0059ac288b0de453ccd93f13cd2364cd_14ef52e5-8bdd-473c-b844-54c1ee27ca60"

# this is likely utf16 encoded
# #0 is 1 and others are 0
$bytes[0..7]

# 8-11 some number?
# 72 0 0 0 
$bytes[8..11]

#5 0 3 0
$bytes[12..15]

# 178 1 0 0
$bytes[16..19]

# 114 1 0 0
$bytes[20..23]

# 140 1 0 0
$bytes[24..27]

# 16 zeroes
$bytes[28..43]

# text
# some guid (length is 72 + 1 byte just like bytes 8..11)
# d0da4acd-810b-4e61-a880-763ce54ded89,
[System.Text.Encoding]::Unicode.GetString($bytes[44..117])

# 10 zeroes
$bytes[118..127]

# 16 0 0 0
$bytes[128..131]

# 8 0 0 0
$bytes[132..135]

#text, length is 16 bytes just like 128..131
#Modified
[System.Text.Encoding]::Unicode.GetString($bytes[136..151])

# 80 177 241 82 106 154 220 1
$bytes[152..159]

# 10 1 0 0
$bytes[160..163]

# 32 0 0 0
$bytes[164..167]

# 0 0 0 0
$bytes[168..171]

# 36 0 0 0
$bytes[172..175]

# 210 0 0
$bytes[176..179]

# 210 + 36
# CreatorProcessNameC:\Program Files\WindowsApps\Microsoft.YourPhone_1.25112.36.0_x64__8wekyb3d8bbwe\PhoneExperienceHost.exe
[System.Text.Encoding]::Unicode.GetString($bytes[180..425])

# 124 0 0 0
$bytes[426..429]

# 10 0 0 0
$bytes[430..433]

# 0 0 0 0
$bytes[434..437]

# 0 0 0 0
$bytes[438..441]

# 104 0 0 0
$bytes[442..445]

# bunch of numbers
# 69 67 83 51 48 0 0 0 68 86 61 206 198 22 53 175 236 120 86 137 40 166 251 192 4 106 54 199 25 86 136 222 141 242 114 157 215 245 249 203 202 237 107 189 135 215 202 150 162 118 56 80 72 153 198 212 0 102 236 180 79 19 110 93 82 208 244 46 24 168 118 46 253 219 207 192 114 15 54 11 9 41 244 141 115 91 157 34 139 86 45 46 172 228 220 86 4 75 240 61 8 208 71 133
$bytes[446..549]

# 1 0 0 0 
$bytes[550..553]

# 16 numbers?
# 208 140 157 223 1 21 209 17 140 122 0 192 79 194 151 235
$bytes[554..569]

# 1 0 0 0 
$bytes[570..573]

# 16 numbers?
# 152 148 97 107 34 96 63 74 132 213 89 13 18 197 80 110
$bytes[574..589]

# 0 0 0 0 
$bytes[590..593]

# 46 0 0 0 
$bytes[594..597]

# length is 46
# Private Key Properties
[System.Text.Encoding]::Unicode.GetString($bytes[598..643])

# 16 102 0 0
$bytes[644..647]

# 0 1 0 0
$bytes[648..651]

# 32 0 0 0
$bytes[652..655]

# 32 bytes
# 30 188 116 221 68 167 124 166 151 121 210 98 154 19 188 216 202 193 106 38 116 115 75 151 146 168 180 84 238 109 135 197
$bytes[656..687]

# 0 0 0 0
$bytes[688..691]

# 14 128 0 0
$bytes[692..695]

# 0 2 0 0
$bytes[696..699]

# 32 0 0 0
$bytes[700..703]

# 32 bytes
# 241 184 57 107 86 153 43 135 1 63 219 50 39 75 206 227 154 80 9 218 178 125 187 17 12 128 141 212 114 52 147 89
$bytes[704..735]

# 112 0 0 0
$bytes[736..739]

# 112 bytes
$bytes[740..851]

# 64 0 0 0
$bytes[852..855]

# 64 bytes
$bytes[856..919]

# 1 0 0 0
$bytes[920..923]

# 16 chars?
# 208 140 157 223 1 21 209 17 140 122 0 192 79 194 151 235
$bytes[924..939]

# 1 0 0 0
$bytes[940..943]

# 16 bytes?
# 152 148 97 107 34 96 63 74 132 213 89 13 18 197 80 110
$bytes[944..959]

# 0 0 0 0
$bytes[960..963]

# 24 0 0 0
$bytes[964..967]

# Private Key
[System.Text.Encoding]::Unicode.GetString($bytes[968..991])

# 16 102 0 0
$bytes[992..995]

# 0 1 0 0
$bytes[996..999]

# 32 0 0 0
$bytes[1000..1003]

# 32 bytes?
# 86 10 61 75 5 198 107 102 30 217 166 21 233 146 254 17 86 72 197 32 88 122 97 127 32 73 51 11 67 111 137 253
$bytes[1004..1035]

# 0 0 0 0
$bytes[1036..1039]

# 14 128 0 0
$bytes[1040..1043]

# 0 2 0 0
$bytes[1044..1047]

# 32 0 0 0
$bytes[1048..1051]

# 32 bytes?
# 180 46 21 130 48 41 250 147 255 209 133 140 106 34 199 2 250 24 229 115 191 221 173 83 205 5 124 68 34 236 40 30
$bytes[1052..1083]

# 160 0 0 0
$bytes[1084..1087]

# 160 bytes
# 105 85 143 131 67 83 43 119 198 70 50 128 79 192 31 237 177 89 31 217 91 184 75 212 195 104 160 92 63 66 4 77 224 156 222 68 12 113 125 91 242 11 53 51 156 91 254 43 116 159 175 8 153 120 126 229 29 144 174 171 190 243 81 44 222 231 213 50 73 71 229 123 29 154 120 119 129 190 16 225 42 105 142 17 130 21 45 91 97 149 101 230 194 140 189 149 98 227 118 189 20 205 105 122 203 95 197 129 252 5 193 65 149 7 198 203 131 156 242 164 255 73 187 234 9 124 153 14 153 158 119 127 91 109 16 42 185 219 168 213 146 54 17 4 159 136 137 92 141 233 77 180 234 124 220 94 95 153 37 135
$bytes[1088..1247]

# 64 0 0 0
$bytes[1248..1251]

#64 bytes
# 166 205 244 242 159 163 254 248 185 4 132 28 64 56 148 60 74 1 99 160 233 139 68 57 120 62 4 57 173 146 45 167 175 33 43 199 142 105 205 56 151 230 219 96 180 254 139 17 124 243 65 205 226 185 13 40 188 196 135 44 170 20 205 231
$bytes[1252..1315]

# that's the last of it. 

#  certutil.exe -user -store My
# Serial Number: a9ccdba4c5c60f7e
# Issuer: CN=1f04603b-aeb2-41b4-9ca8-0a351b2f52c5
#  NotBefore: 1/10/2026 2:09 PM
#  NotAfter: 1/11/2027 2:09 AM
# Subject: CN=1f04603b-aeb2-41b4-9ca8-0a351b2f52c5
# Signature matches Public Key
# Root Certificate: Subject matches Issuer
# Cert Hash(sha1): f9a4c0ee820a7a827cebaed6ba71310dc1d2d095
#   Key Container = 03614abf-9ab9-4ab5-9f1c-343336c1f553
#   Unique container name: cb7f3b169ea1a1fc587a06bb5818497c_14ef52e5-8bdd-473c-b844-54c1ee27ca60
#   Provider = Microsoft Software Key Storage Provider
# Private key is NOT exportable
# Signature test passed
# 
# C:\Users\leppa\AppData\Roaming\Microsoft\Crypto\Keys
C:\Users\leppa\AppData\Roaming\Microsoft\Crypto\Keys\cb7f3b169ea1a1fc587a06bb5818497c_14ef52e5-8bdd-473c-b844-54c1ee27ca60