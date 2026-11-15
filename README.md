PStory (Poketibia - OTClient Fork) — Asset Encryption Analysis
pstory_dx.exe (32-bit PE, x86), image base 0x00400000, runtime base 0x00AB0000, Asset container: PStory\game\content\data.zip


1. Overview
The game does not store raw assets in data.zip. Instead, every file inside the ZIP is wrapped in a custom container format identified by the magic ENC3.
The decryption pipeline is:

ZIP entry → ENC3 container → derive per-file key/IV → AES-128-CTR decrypt → zlib inflate → original file
The encryption is not ZipCrypto, WinZip AES, or any standard ZIP encryption. It is a custom scheme built on top of the Crypto++ library (statically linked).

The trailer bytes at the end of each ENC3 container act as a per-file salt.
There is no global AES key — every ZIP entry has its own unique AES key and IV derived from the hardcoded passwords plus that file's trailer bytes.

2. Hardcoded Key Material
Two password strings are baked into the .rdata section. They are copied into heap buffers at runtime by FUN_00482570 and FUN_004825f0.

Password 1 — Key derivation seed
Field	Value
Virtual Address	0x00d35788
Length	59 bytes (0x3b)
Raw bytes (hex)	4b 36 77 21 5e 6f 33 54 23 48 38 7d 69 4c 30 42 7b 70 37 2b 67 45 26 58 35 6a 24 51 6d 32 40 52 7c 64 39 61 56 31 4e 25 53 28 34 6c 55 29 66 2a 5a 7e 43 5b 59 65 46 68 47 74 5d 00
ASCII	`K6w!^o3T#H8}iL0B{p7+gE&X5j$Qm2@R

Password 2 — IV derivation seed
Field	Value
Virtual Address	0x00d357c4
Length	58 bytes (0x3a)
Raw bytes (hex)	41 26 33 6b 23 75 39 58 31 57 5e 64 52 38 7a 40 47 28 35 70 51 37 74 24 43 2a 48 7d 4c 30 46 34 7e 6a 25 56 32 6f 21 4e 7b 79 29 5a 6c 53 36 69 7c 42 5b 65 2b 4f 6d 67 54 5d 00
ASCII	`A&3k#u9X1W^dR8z@G(5pQ7t$C*H}L0F4~j%V2o!N{y)ZlS6i

3. Key Derivation Function (KDF)

The KDF is not PBKDF2, scrypt, or Argon2. It is a custom home-brew construction.

3.1 Step 1 — Salted password
The password string (from §2) is concatenated with the literal suffix "PStory":

input = password + "PStory"
3.2 Step 2 — State-machine mixing
Two state arrays are maintained:

state32[32] — 32-byte array, zero-initialized
state8[8] — 8-byte array, zero-initialized
For each byte b = input[i]:

tmp      = b ^ state32[i & 0x1f]
state32[i & 0x1f] = ROL8(tmp, 3)   # (tmp << 3 | tmp >> 5) & 0xFF

tmp2     = b ^ state8[i & 7]
state8[i & 7]     = ROL8(tmp2, 5)  # (tmp2 << 5 | tmp2 >> 3) & 0xFF
3.3 Step 3 — Salsa20 keystream generation
The final state32 (32 bytes) is used as a Salsa20 key, and state8 (8 bytes) is used as a Salsa20 nonce/IV.

Object constructed: CryptoPP::SymmetricCipherFinal<…, CryptoPP::Salsa20_Info>
Setup call: SetKeyWithIV(state32, 0x20, state8, 8)
The KDF then encrypts the trailer bytes (not a zero-filled buffer) with Salsa20.
Because Salsa20 is a stream cipher, encryption is just XOR with the keystream:

derived_material = Salsa20_keystream(trailer_bytes) ⊕ trailer_bytes
The trailer bytes are the plaintext input to Salsa20.
Since ciphertext = plaintext ⊕ keystream, rearranging gives keystream = ciphertext ⊕ plaintext.
The KDF outputs the ciphertext (i.e. keystream ⊕ trailer), which is exactly what becomes the AES key/IV.

3.4 Step 4 — Material split
The caller (FUN_005da670) takes the first N bytes from each derivation:

16 bytes → AES-128 key
12 bytes → AES IV
Because the trailer bytes differ for every file, every ZIP entry has a unique AES key and IV.

4. File Container Format (ENC3)
Magic string: ENC3 (found at 0x00d46608)
Validation function: FUN_005da670

Layout of a single ZIP entry after extraction
+0x00  : 4 bytes   — "ENC3" magic
+0x04  : 4 bytes   — unknown header / flags
+0x08  : N bytes   — AES-encrypted payload
         N = file_size - 0x24 - 8 = file_size - 0x2C
-end   : 0x1c bytes — trailer part 1 (28 bytes from end)
         └─ 16 bytes at offset = size - 0x1c  → fed into KDF as salt for key
         └─ 12 bytes at offset = size - 0x0c  → fed into KDF as salt for IV
Total trailer size: 28 bytes (16 + 12).

5. Decryption Layer
Function: FUN_0082fea0 (0x0082fea0)

5.1 Cipher configuration
Parameter	Value
Algorithm	AES-128 (Rijndael)
Mode	CTR
Key size	16 bytes
IV/Nonce size	12 bytes
Counter format	12-byte nonce
Counter initial value	2
5.2 Crypto++ objects observed
CryptoPP::BlockCipherFinal<0, CryptoPP::Rijndael::Enc> — AES encryptor (CTR uses encryption for both directions)
CryptoPP::SymmetricCipherFinal<…, CryptoPP::Salsa20_Info> — Salsa20 stream cipher (used only inside the KDF)
Correction: the CTR counter in Crypto++ starts at 2, not 0 or 1.
In pycryptodome terms: Counter.new(32, prefix=iv, initial_value=2, little_endian=False).

6. Decompression Layer
After AES-CTR decryption, the plaintext is passed to:

Function: FUN_0083a910 (0x0083a910)
Library: zlib / inflate (strings like "inflate 1.3.1 Copyright 1995-2024 Mark Adler" are present in the binary)

Failure to decompress produces the log message:

Decompression failed: expected %u, got %lu
(found at 0x00d468d4, referenced from 0x005daa3c)

7. Full Decryption Algorithm (Python)
import zipfile
import zlib
from Crypto.Cipher import AES, Salsa20
from Crypto.Util import Counter

# Exact password bytes from .rdata
PWD1 = bytes.fromhex(
    "4b3677215e6f33542348387d694c3042"
    "7b70372b67452658356a24516d324052"
    "7c64396156314e255328346c5529662a"
    "5a7e435b5965466847745d"
)
PWD2 = bytes.fromhex(
    "4126336b2375395831575e6452387a40"
    "4728357051377424432a487d4c304634"
    "7e6a2556326f214e7b79295a6c533669"
    "7c425b652b4f6d67545d"
)

def derive_password_state(password: bytes) -> bytes:
    data = password + b"PStory"
    state32 = [0] * 32
    state8  = [0] * 8
    for i, b in enumerate(data):
        tmp  = b ^ state32[i & 0x1f]
        state32[i & 0x1f] = ((tmp << 3) | (tmp >> 5)) & 0xff
        tmp2 = b ^ state8[i & 7]
        state8[i & 7]     = ((tmp2 << 5) | (tmp2 >> 3)) & 0xff
    return bytes(state32) + bytes(state8)

state1 = derive_password_state(PWD1)
state2 = derive_password_state(PWD2)
ks1 = Salsa20.new(key=state1[:32], nonce=state1[32:]).encrypt(bytes(32))
ks2 = Salsa20.new(key=state2[:32], nonce=state2[32:]).encrypt(bytes(32))

def decrypt_enc3(data: bytes) -> bytes:
    if len(data) < 0x24 or data[:4] != b"ENC3":
        raise ValueError("Not a valid ENC3 container")

    trailer_key = data[len(data) - 0x1c : len(data) - 0x1c + 0x10]   # 16 bytes
    trailer_iv  = data[len(data) - 0x0c :]                            # 12 bytes

    key = bytes(k ^ t for k, t in zip(ks1[:16], trailer_key))
    iv  = bytes(k ^ t for k, t in zip(ks2[:12], trailer_iv))

    # AES-128-CTR, BE counter, starts at 2
    cipher = AES.new(
        key, AES.MODE_CTR,
        counter=Counter.new(32, prefix=iv, initial_value=2, little_endian=False)
    )

    encrypted = data[8 : len(data) - 0x1c]   # skip 8-byte header, 28-byte trailer
    decrypted = cipher.decrypt(encrypted)
    return zlib.decompress(decrypted)
    
8. Relevant Ghidra Symbols
Purpose	Function	Address (Ghidra)	Runtime address (base 0xAB0000)
ZIP mounting / file read	FUN_005d1280	0x005d1280	0x0C21280
ENC3 container handler	FUN_005da670	0x005da670	0x0C8A670
KDF (Salsa20-based)	FUN_00830590	0x00830590	0x0E30590
AES-128-CTR decrypt	FUN_0082fea0	0x0082fea0	0x0EDFEA0
zlib inflate wrapper	FUN_0083a910	0x0083a910	0x0EEA910
Key init (password 1)	FUN_00482570	0x00482570	0x0F32570
Key init (password 2)	FUN_004825f0	0x004825f0	0x0F325F0
String compare / magic check	FUN_0049bfc0	0x0049bfc0	0x0F4BFC0
String assign helper	FUN_005dbc80	0x005dbc80	0x0C8BC80

10. Appendix — Raw Data Addresses
Address	Content
0x00d35788	Password 1 (59 bytes, null-terminated)
0x00d357c4	Password 2 (58 bytes, null-terminated)
0x00d46494	"data.zip" string
0x00d46608	"ENC3" magic
0x010058a0	Runtime pointer to password #1 (rebased: 0x16B58A0)
0x010058d0	Runtime pointer to password #2 (rebased: 0x16B58D0)
