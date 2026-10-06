# pca-java

Proof-Carrying Authority (PCA) verifier for Java. **Preview.**

PCA is authF: instead of verifying a token, you verify a proof-carrying action (a PCActn) - the capability chain, Merkle plan inclusion, Ed25519 leaf signature and counter. This is a reference verifier that passes the shared conformance vectors.

> Preview: the wire format and API may change before 1.0.

## Install

Preview, not yet on Maven Central. Planned coordinate: `net.atlasauth:atlas-pca`. For now, copy `src/net/atlasauth/pca` into your project (no dependencies; JDK 17+).

## Verify

```java
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Json;

Map<String, Object> pcactn = (Map<String, Object>) Json.parse(pcactnJson);
Map<String, Object> grant  = (Map<String, Object>) Json.parse(grantJson);
Pca.Verdict v = Pca.verifyPcactnCore(pcactn, grant);
if (v.allow) {
    // chain, plan_inclusion, leaf_signature, counter all passed
} else {
    System.out.println(v.reason + " " + v.checks);
}
```

## Conformance tests

The shared golden vectors are vendored in `conformance/` (synced from the hub). Run:

```
d=$(mktemp -d) && javac -d $d src/net/atlasauth/pca/*.java ConformanceTest.java && java -cp $d ConformanceTest
```

The reference verifier must produce the same `allow` and the same pass/fail for each of the four checks on every vector.

## Links

- Hub (spec, other languages): https://github.com/Atlas-Authorization/pca
- Live docs: https://atlasauth.net/pca
- TypeScript reference: npm `@atlasauth/pca`

## License

MIT
