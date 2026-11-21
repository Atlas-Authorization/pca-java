# PCA Java adapters

Each directory is its own Maven module (`net.atlasauth`), depending on the core library (`net.atlasauth:pca-mutation:0`, installed
first with `mvn -Dmaven.test.skip=true install` in the pca-java root). The core pom has none of these dependencies.

| Module | What |
| --- | --- |
| [pca-spring-security](pca-spring-security) | Spring Security 6.2+: authentication filter and provider, `http.with(PcaSecurity.pca(...))`, authorities from the action, `@PreAuthorize` helper |
| [pca-spring-boot-starter](pca-spring-boot-starter) | Spring Boot 3.x auto-configuration from `pca.*` properties |
| [pca-jaxrs](pca-jaxrs) | Jakarta REST filter and `@PcaProtected` name binding (also notes the EE 10 servlet `PcaFilter`) |
| [pca-mpc-lwe-ot](pca-mpc-lwe-ot) | Post-quantum endemic base OT (Kyber-768 K-PKE via JNA over liblweot), including `EndemicOtNet`, the networked variant the party program (`ot.kind` "lwe") loads by reflection when this module is on the classpath |
| [pca-zk](pca-zk) | Groth16 verification and proving of snarkjs artifacts on BN254 and BLS12-381 (JNA over libpcazk): `NativeZk.register()` installs the engine the core `Zk` class (Policy VM and compliance proof verifiers, `createZkVerifier` backends) needs |

Native modules (`pca-pairing`, `pca-mpc-lwe-ot`, `pca-fndsa`, `pca-zk`, `pca-fhe-seal`, and the LESS verifier in the core jar) carry their libraries inside their jar under
`natives/<os>-<arch>/` for linux x64/arm64, macOS x64/arm64 and windows x64, and extract the one for the running platform on first use; nothing to install or
build. A library path you set yourself (`-Dpca.gt.lib`, `-Dpca.sealc.lib`, `-Dpca.lweot.lib`, `-Dpca.fndsa.lib`, `ATLAS_PCA_LIBFNDSA`, `-Dpca.zk.lib`, `ATLAS_PCA_LIBPCAZK`, `ATLAS_PCA_LIBLESS`) is used instead of the packaged one.
`pca-wasm-chicory` is pure Java.

The starter depends on `pca-spring-security` (optional), so install that first.
