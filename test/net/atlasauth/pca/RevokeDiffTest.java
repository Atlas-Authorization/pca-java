package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.FileRevocationStore;
import net.atlasauth.pca.revoke.InMemoryRevocationStore;
import net.atlasauth.pca.revoke.JsVal;
import net.atlasauth.pca.revoke.RevocationEntry;
import net.atlasauth.pca.revoke.RevocationRegistry;
import net.atlasauth.pca.revoke.RevocationStore;
import net.atlasauth.pca.revoke.RevocationStoreConformance;
import net.atlasauth.pca.revoke.Revoke;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RevokeDiffTest {
    private static final String M = "ref-revoke";
    /** The frozen clock the corpus generator ran under (its header's clockMs). */
    private static final double CLOCK_MS = BaseOracle.clockMs(M);

    /** A store whose get (or all) throws, as the oracle's failing stores do. */
    private static final class Failing implements RevocationStore {
        final InMemoryRevocationStore base = new InMemoryRevocationStore();
        final boolean failGet;
        Failing(boolean failGet) { this.failGet = failGet; }
        public void add(RevocationEntry e) { base.add(e); }
        public boolean remove(String k, String v) { return base.remove(k, v); }
        public RevocationEntry get(String k, String v) { if (failGet) throw new IllegalStateException("boom"); return base.get(k, v); }
        public List<RevocationEntry> all() { if (!failGet) throw new IllegalStateException("boom"); return base.all(); }
        public void clear() { base.clear(); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) {
        if (o == null) return null;
        if (!(o instanceof Map)) throw new JsVal.TypeError("not an object");
        return (Map<String, Object>) o;
    }

    private static List<Object> entries(List<RevocationEntry> es) {
        List<Object> out = new ArrayList<>();
        for (RevocationEntry e : es) out.add(e.toMap());
        return out;
    }

    /** An entry whose revokedAt is within two minutes of the wall clock, or of the corpus generator's frozen clock, prints as "<now>" (the reference does the same). */
    @SuppressWarnings("unchecked")
    private static Object norm(Object v) {
        if (v instanceof List) { List<Object> o = new ArrayList<>(); for (Object x : (List<Object>) v) o.add(norm(x)); return o; }
        if (v instanceof Map) {
            Map<String, Object> o = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                Double d = JsVal.num(e.getValue());
                o.put(e.getKey(), e.getKey().equals("revokedAt") && d != null && (Math.abs(d - System.currentTimeMillis()) < 120_000 || Math.abs(d - CLOCK_MS) < 120_000) ? "<now>" : norm(e.getValue()));
            }
            return o;
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    static Object scenario(Object specO) {
        Map<String, Object> spec = (Map<String, Object>) specO;
        Object st = spec.get("store");
        RevocationStore store = "failGet".equals(st) ? new Failing(true) : "failAll".equals(st) ? new Failing(false) : new InMemoryRevocationStore();
        RevocationRegistry reg = new RevocationRegistry(store);
        List<Object> out = new ArrayList<>();
        for (Object so : (List<Object>) spec.get("ops")) {
            Map<String, Object> s = (Map<String, Object>) so;
            try {
                Object r;
                switch ((String) s.get("op")) {
                    case "revoke": r = reg.revoke(map(s.get("input"))).toMap(); break;
                    case "revokeSubtree": r = reg.revokeSubtree(s.get("target"), map(s.get("opts"))).toMap(); break;
                    case "unrevoke": r = reg.unrevoke(map(s.get("key"))); break;
                    case "list": r = entries(reg.list()); break;
                    case "lookup": { RevocationEntry e = reg.lookup((String) s.get("kind"), (String) s.get("value")); r = e == null ? null : e.toMap(); break; }
                    case "prefixes": r = entries(reg.prefixes()); break;
                    case "clear": reg.clear(); r = null; break;
                    case "killAgent": r = reg.killAgent(s.get("holder"), map(s.get("opts"))).toMap(); break;
                    case "killSubtree": r = reg.killSubtree(s.get("root"), map(s.get("opts"))).toMap(); break;
                    case "check": r = Revoke.checkRevocation(s.get("p"), reg, map(s.get("opts"))).toMap(); break;
                    case "verify": r = Revoke.verifyWithRevocation(s.get("p"), s.get("core"), reg, map(s.get("opts"))).toMap(); break;
                    case "ingest": r = entries(Revoke.ingestCaepEvent(s.get("event"), reg)); break;
                    default: throw new IllegalArgumentException("bad op");
                }
                out.add(norm(r));
            } catch (RuntimeException e) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("$err", true);
                out.add(err);
            }
        }
        return out;
    }

    @Test void scenarios() throws Exception { OracleCases.each(M, "scenario", a -> scenario(a.get(0))); }

    @Test void isActiveAt() throws Exception {
        OracleCases.each(M, "isActiveAt", a -> {
            Map<String, Object> e = map(a.get(0));
            Double nb = e.containsKey("notBefore") ? JsVal.num(e.get("notBefore")) : null;
            if (e.containsKey("notBefore") && nb == null) nb = Double.NaN;
            Double now = JsVal.num(a.get(1));
            RevocationEntry r = new RevocationEntry("cap", "v", null, "", 1, nb);
            return Revoke.isActiveAt(r, now == null ? Double.NaN : now);
        });
    }

    @Test void caepEventTypes() throws Exception {
        OracleCases.each(M, "caepEventTypes", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("sessionRevoked", Revoke.SESSION_REVOKED);
            m.put("grantRevoked", Revoke.GRANT_REVOKED);
            m.put("killSwitch", Revoke.KILL_SWITCH);
            return m;
        });
    }

    @Test void inMemoryStoreConformance() throws Exception {
        for (RevocationStoreConformance.Case c : RevocationStoreConformance.cases(InMemoryRevocationStore::new, null)) c.run.run();
    }

    @Test void fileStoreConformanceAndDurability(@TempDir Path dir) throws Exception {
        int[] n = {0};
        Path[] last = new Path[1];
        for (RevocationStoreConformance.Case c : RevocationStoreConformance.cases(
            () -> { last[0] = dir.resolve("rev" + (n[0]++) + ".json"); return new FileRevocationStore(last[0]); },
            prev -> new FileRevocationStore(last[0]))) c.run.run();
    }

    @Test void fileStoreRefusesACorruptFile(@TempDir Path dir) throws Exception {
        Path p = dir.resolve("rev.json");
        for (String bad : new String[] {"not json", "{}", "{\"entries\":{}}", "{\"entries\":[{\"kind\":\"cap\"}]}",
            "{\"entries\":[{\"kind\":\"prefix\",\"value\":\"a,b\",\"prefix\":[\"a\"],\"reason\":\"\",\"revokedAt\":1}]}",
            "{\"entries\":[{\"kind\":\"cap\",\"value\":\"c\",\"reason\":\"\",\"revokedAt\":1,\"notBefore\":null}]}"}) {
            Files.write(p, bad.getBytes(StandardCharsets.UTF_8));
            assertThrows(IllegalStateException.class, () -> new FileRevocationStore(p), bad);
        }
        Files.write(p, "{\"v\":1,\"entries\":[{\"kind\":\"cap\",\"value\":\"c\",\"reason\":\"r\",\"revokedAt\":1,\"notBefore\":2}]}".getBytes(StandardCharsets.UTF_8));
        FileRevocationStore ok = new FileRevocationStore(p);
        assertEquals(1, ok.all().size());
        assertTrue(ok.get("cap", "c").notBefore == 2.0);
    }
}
