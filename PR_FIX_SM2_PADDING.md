# PR: SM2 alignment fixes — address derivation padding & Z_A 32-byte padding (OpenSSL / GM/T 0003)

## 标题 (Title)

**smcrypto: fix SM2 address derivation padding and align Z_A with OpenSSL 32-byte padding (GM/T 0003)**

---

## 修改说明 (Summary)

This PR includes two smcrypto fixes:

### 1. SM2 public key / address derivation (right-align padding)

- **SM2PubBytes** and **Sign** now encode public key coordinates X, Y as **32-byte big-endian right-aligned** (left-pad with zeros) so that address derivation is consistent when coordinates have leading zeros.
- Ensures addresses computed from SM2 public keys match expectations and are stable for short or leading-zero coordinates.

### 2. SM2 Z_A computation aligned with OpenSSL (32-byte padding per GM/T 0003)

When the FISCO BCOS chain or bcos-crypto is built with **WITH_SM2_OPTIMIZE**, it uses OpenSSL's `sm2_do_sign`, which computes the SM2 user digest **Z_A** via `sm2_compute_z_digest`. In OpenSSL, the curve parameters and public key coordinates **(a, b, xG, yG, xA, yA)** are each encoded as **exactly 32 bytes**, big-endian, **left-padded with zeros** (`BN_bn2binpad(..., p_bytes)`).

The go-sdk previously used `big.Int.Bytes()` for these six values, which produces **variable-length** octet strings (no leading zeros). As a result, **Z_A computed in Go differed from Z_A computed in OpenSSL**, so the signed digest **e = SM3(Z_A || M)** differed. That caused **InvalidSignature** on the chain when the node verifies with OpenSSL-style Z_A.

This change updates **SM2PreProcess** in `v3/smcrypto/sm2.go` to encode a, b, Gx, Gy, and the public key coordinates X, Y as **32-byte big-endian left-padded** values, matching OpenSSL and GM/T 0003. Signatures produced by go-sdk then verify correctly on chains using bcos-crypto with **WITH_SM2_OPTIMIZE**.

---

## 修改内容 (Changes)

### File: `v3/smcrypto/sm_crypto.go`

- **SM2PubBytes**: Encode X, Y as 64 bytes total with each coordinate **right-aligned** in its 32-byte half (left-pad with zeros).
- **Sign**: Build signature R\|S\|V with the same 32-byte right-aligned public key encoding for V.

### File: `v3/smcrypto/sm2.go`

1. **Added** constant `sm2FieldBytes = 32` (SM2 curve field size in bytes).
2. **Added** helper `bigIntTo32Bytes(n *big.Int) []byte`: encodes `n` as 32-byte big-endian with left zero-padding (same semantics as OpenSSL `BN_bn2binpad(n, buf, 32)`).
3. **Updated** `SM2PreProcess`:
   - Use a single `params := elliptic.Sm2p256v1().Params()` for clarity.
   - Replace all six `params.A.Bytes()`, `params.B.Bytes()`, `params.Gx.Bytes()`, `params.Gy.Bytes()`, `priv.X.Bytes()`, `priv.Y.Bytes()` with **`bigIntTo32Bytes(params.A)`**, **`bigIntTo32Bytes(params.B)`**, **`bigIntTo32Bytes(params.Gx)`**, **`bigIntTo32Bytes(params.Gy)`**, **`bigIntTo32Bytes(priv.X)`**, **`bigIntTo32Bytes(priv.Y)`**.
   - Comment updated to state alignment with OpenSSL and bcos-crypto WITH_SM2_OPTIMIZE.

No API changes. For standard FISCO BCOS nodes using OpenSSL/bcos-crypto WITH_SM2_OPTIMIZE, the Z_A fix is **required** for signatures to verify.

---

## 原因与背景 (Reason & context)

- **Address padding:** Public key coordinates from `big.Int.Bytes()` are variable-length; address derivation must use a fixed 32-byte-per-coordinate encoding (right-aligned) so addresses are deterministic and match chain/tooling expectations.
- **GM/T 0003-2012** specifies Z_A = H(ENTL \|\| ID \|\| a \|\| b \|\| x_G \|\| y_G \|\| x_A \|\| y_A). The standard and common implementations (e.g. OpenSSL) use **fixed-length** encoding for the curve and point coordinates (e.g. 32 bytes for SM2's prime field).
- **OpenSSL** `sm2_compute_z_digest` uses `BN_bn2binpad` with `p_bytes` (32), so each of a, b, xG, yG, xA, yA is 32 bytes, big-endian, left-padded.
- **bcos-crypto** (WITH_SM2_OPTIMIZE) calls OpenSSL's `sm2_do_sign`, which uses that Z_A. Chain verification therefore expects signatures generated with the same Z_A.
- **go-sdk** previously built Z_A with variable-length `.Bytes()`, so Z_A (and hence e = SM3(Z_A \|\| M)) did not match OpenSSL, leading to **InvalidSignature** on the chain even when the key and message were correct.

---

## 测试建议 (Testing)

- Unit test: `v3/smcrypto` — `TestHexToSM2`, `TestSM2PubBytes_RightAlignedPadding`; same (message, key) → sign with go-sdk and with OpenSSL (or bcos-crypto FastSM2); compare R, S (or full signature); verify cross-verification.
- Integration: build encoded transaction with go-sdk, send to a node built with bcos-crypto WITH_SM2_OPTIMIZE; confirm transaction is accepted (no InvalidSignature).
- From repo root: `make test` runs v3 smcrypto (and abi/flags) unit tests.

---

## 参考 (References)

- OpenSSL: `crypto/sm2/sm2_sign.c` — `sm2_compute_z_digest` uses `BN_bn2binpad(..., p_bytes)` for a, b, xG, yG, xA, yA.
- GM/T 0003.2-2012 (SM2 digital signature).
- bcos-crypto: `signature/fastsm2/fast_sm2.cpp` — `sm2_do_sign(..., raw_message_hash)` with OpenSSL.
