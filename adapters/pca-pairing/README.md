# pca-pairing

Pairing-based PCA packages for Java on BLS12-381, kept out of the core library so the core pom gains no native dependency.

| Java package | PCA package | Contents |
| --- | --- | --- |
| `net.atlasauth.pca.aggsig` | `pca-aggsig` | BLS signatures (PoP ciphersuite), rogue-key-safe `RegisteredKey` / `KeyRegistry`, BLS capability chain, witness cosignature aggregation |
| `net.atlasauth.pca.bbs` | `pca-bbs` | BBS signatures (BLS12-381-SHA-256), selective-disclosure proofs, capability credentials |
| `net.atlasauth.pca.abe` | `pca-abe` | FAME ciphertext-policy ABE (AES-256-GCM payload, authenticated header), capability-bound keys, tool-payload encryption |
| `net.atlasauth.pca.pairing` | (shared) | `Bls12`: scalar field helpers, expand_message_xmd, strict point decoding, pairing equality; `Gt`: target-group operations |

## Pairing library

All curve and pairing work is [supranational blst](https://github.com/supranational/blst) (audited, constant-time, Apache-2.0) through its JVM binding
`tech.pegasys:jblst` 0.3.18 (Maven Central, natives bundled for Linux, macOS and Windows). Nothing in this module implements a pairing or a field.
BouncyCastle has no BLS12-381 pairing; the other JVM options surveyed (Besu/gnark native, Tuweni/Milagro) are either too narrow or unaudited.

## GT shim (ABE)

jblst's `PT` has no GT parsing or exponentiation, which FAME needs. `src/main/c/pca_gt.c` adds them as plain C over blst's public API
(Fp12 multiply and square, Miller loop, final exponentiation, point decoding and subgroup checks; exponentiation is a Montgomery ladder with a
branch-free swap), and `pca_gt_jni.c` binds it to `net.atlasauth.pca.pairing.Gt`. No field or curve arithmetic is implemented in the shim. Build it
into one shared library together with blst (`cc -shared -fPIC pca_gt.c pca_gt_jni.c blst/src/server.c blst/build/assembly.S`, as the pairing CI workflow does)
and point `-Dpca.gt.lib` at it; `mvn test` reads `pca.gt.lib` (default `target/native/libpcagt.so`). A missing library is a `LinkageError`, never a "bad input" result.

## Build

Install the core library into the local repository first (`mvn install` in `sdks/java-pca`), then `mvn test` here. Tests replay the vendored community vectors
(ethereum/bls12-381-tests, the draft-irtf-cfrg-bbs-signatures fixtures, an RFC 9380 expand_message_xmd vector) and the TypeScript-reference corpora in `test-data/`.

## Not ported

- `pca-fhe`: needs Microsoft SEAL; there is no vetted JVM binding.
- `pca-mpc`: not yet ported.

## Limits

Scalar-field arithmetic (add, multiply, inverse mod r) is `BigInteger`, which is not constant-time; the key-dependent point multiplications are blst's constant-time code.
