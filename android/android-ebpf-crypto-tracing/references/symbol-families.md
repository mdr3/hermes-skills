# Symbol families and argument layouts

All arm64 AAPCS: x0..x7 are args, x30 is the return address. Data pointers are
often MTE-tagged; mask before reading.

## OpenSSL / BoringSSL

| symbol | args | capture |
|---|---|---|
| `SSL_write(ssl, buf, n)` | x1 buf, x2 n | plaintext at entry |
| `SSL_read(ssl, buf, n)` | x1 buf, x2 n | plaintext at return (x0 = count) |
| `EVP_CipherInit_ex(ctx, type, e, key, iv, enc)` | x1 cipher struct, x3 key, x4 iv | nid at +0, key_len at +8, iv_len at +12 |
| `EVP_EncryptUpdate/DecryptUpdate(ctx, out, int *outl, in, inl)` | x1 out, x2 outl, x3 in, x4 inl | in at entry, out at return |
| `EVP_AEAD_CTX_init(ctx, aead, key, klen, tag, dir)` | x2 key, x3 klen | key |
| `EVP_AEAD_CTX_seal/open(ctx, out, size_t *outl, max, nonce, nlen, in, inl, ad, adl)` | x1 out, x2 outl, x4 nonce, x6 in, x7 inl | nonce + in at entry, out at return (outl is 8 bytes) |
| `RSA_public_encrypt(flen, from, to, rsa, pad)` | x0 len, x1 in, x2 out | in at entry, out at return |
| `EVP_PKEY_encrypt/decrypt(ctx, out, size_t *outl, in, inl)` | x1 out, x2 outl, x3 in, x4 inl | in at entry, out at return |
| `EVP_DigestFinal_ex(ctx, md, unsigned *s)` / `HMAC_Final(ctx, md, unsigned *s)` | x1 md, x2 s | md at return, cap 64 |

## mbedTLS

- `mbedtls_aes_crypt_cbc(ctx, mode, len, iv, in, out)` — x1 mode, x2 len, x3 iv, x4 in, x5 out.
- `mbedtls_ssl_write(ssl, buf, n)` / `mbedtls_ssl_read(ssl, buf, n)`.

## wolfSSL

- `wolfSSL_write(ssl, data, sz)` / `wolfSSL_read(ssl, data, sz)`.
- `wc_AesCbcEncrypt(aes, out, in, sz)` — note out before in.

## libsodium

- `crypto_secretbox_easy(c, m, mlen, n, k)` — x0 out, x1 m, x2 mlen, x3 nonce(24), x4 key(32).

## Naming helpers

- OpenSSL cipher/digest nids are stable across BoringSSL versions; extract
  `nid -> name` from the target's own libcrypto OBJ table (entries of
  `{long_name, short_name, 0x9_00000000|nid}`) and ship it as a display map.
- `EVP_CIPHER` field offsets (verified on Android 16 libcrypto): nid +0,
  block_size +4, key_len +8, iv_len +0xc, flags +0x14.
