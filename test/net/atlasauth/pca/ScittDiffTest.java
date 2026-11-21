package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.scitt.Cbor;
import net.atlasauth.pca.scitt.DurableTransparencyService;
import net.atlasauth.pca.scitt.FileScittLogStore;
import net.atlasauth.pca.scitt.MemoryScittLogStore;
import net.atlasauth.pca.scitt.Rfc9162;
import net.atlasauth.pca.scitt.Scitt;
import net.atlasauth.pca.scitt.Scitt.CoseAlg;
import net.atlasauth.pca.scitt.ScittLogError;
import net.atlasauth.pca.scitt.ScittLogStore;
import net.atlasauth.pca.scitt.TransparencyService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScittDiffTest {
    private static final String M = "ref-scitt";

    @TempDir Path tmp;

    // ---- argument shaping ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) { return (List<Object>) o; }

    private static boolean isBytes(Object o) { return o instanceof Map && ((Map<?, ?>) o).containsKey("$bytes"); }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) map(o).get("$bytes")); }

    private static List<byte[]> byteList(Object o) {
        List<byte[]> out = new ArrayList<>();
        for (Object x : list(o)) out.add(bytes(x));
        return out;
    }

    private static boolean safe(Object o) { return Json.isSafeInt(o); }

    private static long lng(Object o) { return Json.asLong(o); }

    /** A JSON number as the CBOR model value: Long for an exact safe integer, else Double (which the codec refuses). */
    private static Object num(Json.Num n) {
        String raw = n.raw;
        try {
            java.math.BigDecimal d = new java.math.BigDecimal(raw);
            if (d.signum() == 0 && raw.startsWith("-")) return -0.0;
            java.math.BigInteger i = d.toBigIntegerExact();
            if (i.abs().compareTo(java.math.BigInteger.valueOf(Cbor.MAX_SAFE)) <= 0) return i.longValue();
        } catch (ArithmeticException | NumberFormatException e) {
            // not an exact integer
        }
        return Double.parseDouble(raw);
    }

    private static Object fromCj(Object v) {
        if (v instanceof Json.Num) return num((Json.Num) v);
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : list(v)) out.add(fromCj(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> m = map(v);
            if (m.containsKey("$bytes")) return bytes(m);
            if (m.containsKey("$map")) {
                Map<Object, Object> out = new LinkedHashMap<>();
                for (Object e : list(m.get("$map"))) {
                    List<Object> kv = list(e);
                    out.put(fromCj(kv.get(0)), fromCj(kv.get(1))); // like a JavaScript Map: a repeated key keeps its slot, the last value wins
                }
                return out;
            }
            if (m.containsKey("$tag")) {
                Object t = fromCj(m.get("$tag"));
                if (!(t instanceof Long)) throw new IllegalArgumentException("cbor: bad tag");
                return new Cbor.Tag((Long) t, fromCj(m.get("v")));
            }
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    private static Object toCj(Object v) {
        if (v instanceof Map) {
            List<Object> entries = new ArrayList<>();
            for (Map.Entry<Object, Object> e : ((Map<Object, Object>) v).entrySet()) entries.add(Arrays.asList(e.getKey(), toCj(e.getValue())));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("$map", entries);
            return out;
        }
        if (v instanceof Cbor.Tag) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("$tag", ((Cbor.Tag) v).tag);
            out.put("v", toCj(((Cbor.Tag) v).value));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(toCj(x));
            return out;
        }
        return v;
    }

    private static PrivateKey priv(Object spec) {
        Map<String, Object> s = map(spec);
        if ("EdDSA".equals(s.get("alg"))) return Scitt.ed25519PrivateKey(Keys.unb64u((String) s.get("seed")));
        return Scitt.es256PrivateKey(Keys.unb64u((String) s.get("d")));
    }

    private static PublicKey pub(Object spec) {
        Map<String, Object> s = map(spec);
        if ("EdDSA".equals(s.get("alg"))) return Scitt.ed25519PublicKey(Keys.unb64u((String) s.get("pub")));
        return Scitt.es256PublicKey(Keys.unb64u((String) s.get("x")), Keys.unb64u((String) s.get("y")));
    }

    private static CoseAlg alg(Object o) { return CoseAlg.valueOf((String) o); }

    private static Scitt.SignStatementOpts sOpts(Object o) {
        Map<String, Object> s = map(o);
        Scitt.SignStatementOpts out = new Scitt.SignStatementOpts(alg(s.get("alg")), priv(s.get("key")), (String) s.get("issuer"));
        if (s.containsKey("subject")) out.subject((String) s.get("subject"));
        if (s.containsKey("contentType")) out.contentType((String) s.get("contentType"));
        return out;
    }

    private static Scitt.ReceiptSignerOpts rOpts(Object o) {
        Map<String, Object> s = map(o);
        return new Scitt.ReceiptSignerOpts(alg(s.get("alg")), priv(s.get("key")), (String) s.get("issuer"));
    }

    private static Scitt.VerifyReceiptOpts vOpts(Object o) {
        Scitt.VerifyReceiptOpts out = new Scitt.VerifyReceiptOpts();
        if (!(o instanceof Map)) return out;
        Map<String, Object> m = map(o);
        out.treeRoot = (String) m.get("treeRoot");
        if (m.get("verificationKey") != null) out.verificationKey = pub(m.get("verificationKey"));
        if (m.get("statementKey") != null) out.statementKey = pub(m.get("statementKey"));
        out.allowHighS = Boolean.TRUE.equals(m.get("allowHighS"));
        return out;
    }

    private static boolean highS(List<?> a) { return a.size() > 2 && a.get(2) instanceof Map && Boolean.TRUE.equals(map(a.get(2)).get("allowHighS")); }

    // ---- CBOR ----

    @Test void cborEncode() throws Exception { OracleCases.each(M, "cborEncode", a -> Cbor.encode(fromCj(a.get(0)))); }

    @Test void cborDecode() throws Exception { OracleCases.each(M, "cborDecode", a -> toCj(Cbor.decode(bytes(a.get(0))))); }

    // ---- RFC 9162 ----

    @Test void emptyRoot() throws Exception { OracleCases.each(M, "emptyRoot", a -> Rfc9162.emptyRoot()); }

    @Test void leafHash() throws Exception { OracleCases.each(M, "leafHash", a -> Rfc9162.leafHash(bytes(a.get(0)))); }

    @Test void nodeHash() throws Exception { OracleCases.each(M, "nodeHash", a -> Rfc9162.nodeHash(bytes(a.get(0)), bytes(a.get(1)))); }

    @Test void treeHash() throws Exception { OracleCases.each(M, "treeHash", a -> Rfc9162.treeHash(byteList(a.get(0)))); }

    @Test void inclusionPath() throws Exception {
        OracleCases.each(M, "inclusionPath", a -> {
            if (!safe(a.get(1))) throw new IllegalArgumentException("rfc9162: leaf index out of range");
            return Rfc9162.inclusionPath(byteList(a.get(0)), lng(a.get(1)));
        });
    }

    @Test void rootFromInclusionPath() throws Exception {
        OracleCases.each(M, "rootFromInclusionPath", a ->
            !safe(a.get(1)) || !safe(a.get(2)) ? null : Rfc9162.rootFromInclusionPath(bytes(a.get(0)), lng(a.get(1)), lng(a.get(2)), byteList(a.get(3))));
    }

    @Test void verifyInclusionPath() throws Exception {
        OracleCases.each(M, "verifyInclusionPath", a ->
            safe(a.get(1)) && safe(a.get(2)) && Rfc9162.verifyInclusionPath(bytes(a.get(0)), lng(a.get(1)), lng(a.get(2)), byteList(a.get(3)), bytes(a.get(4))));
    }

    @Test void consistencyPath() throws Exception {
        OracleCases.each(M, "consistencyPath", a -> {
            if (!safe(a.get(1))) throw new IllegalArgumentException("rfc9162: consistency size out of range");
            return Rfc9162.consistencyPath(byteList(a.get(0)), lng(a.get(1)));
        });
    }

    @Test void verifyConsistencyPath() throws Exception {
        OracleCases.each(M, "verifyConsistencyPath", a ->
            safe(a.get(0)) && safe(a.get(1)) && Rfc9162.verifyConsistencyPath(lng(a.get(0)), lng(a.get(1)), bytes(a.get(2)), bytes(a.get(3)), byteList(a.get(4))));
    }

    // ---- proofs, statements, receipts ----

    @Test void siblingSides() throws Exception { OracleCases.each(M, "siblingSides", a -> Scitt.siblingSides(lng(a.get(0)), lng(a.get(1)))); }

    @Test void encodeInclusionProof() throws Exception { OracleCases.each(M, "encodeInclusionProof", a -> Scitt.encodeInclusionProof(map(a.get(0)))); }

    @Test void decodeInclusionProof() throws Exception { OracleCases.each(M, "decodeInclusionProof", a -> Scitt.decodeInclusionProof(bytes(a.get(0)))); }

    @Test void signStatement() throws Exception { OracleCases.each(M, "signStatement", a -> Scitt.signStatement(a.get(0), sOpts(a.get(1)))); }

    @Test void decodeCoseSign1() throws Exception {
        OracleCases.each(M, "decodeCoseSign1", a -> {
            Scitt.CoseSign1 c = Scitt.decodeCoseSign1(bytes(a.get(0)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("protectedBytes", c.protectedBytes);
            m.put("protectedMap", toCj(c.protectedMap));
            m.put("unprotected", toCj(c.unprotected));
            m.put("payload", c.payload);
            m.put("signature", c.signature);
            return m;
        });
    }

    @Test void checkStatement() throws Exception {
        OracleCases.each(M, "checkStatement", a -> Scitt.checkStatement(bytes(a.get(0)), pub(a.get(1)), highS(a)).toMap());
    }

    @Test void verifyStatement() throws Exception {
        OracleCases.each(M, "verifyStatement", a -> Scitt.verifyStatement(bytes(a.get(0)), pub(a.get(1)), highS(a)));
    }

    @Test void statementPayload() throws Exception { OracleCases.each(M, "statementPayload", a -> Scitt.statementPayload(bytes(a.get(0)))); }

    @Test void statementLeaf() throws Exception { OracleCases.each(M, "statementLeaf", a -> Scitt.statementLeaf(bytes(a.get(0)))); }

    @Test void buildReceipt() throws Exception {
        OracleCases.each(M, "buildReceipt", a -> Scitt.buildReceipt((String) a.get(0), map(a.get(1)), rOpts(a.get(2))));
    }

    @Test void verifyReceipt() throws Exception {
        OracleCases.each(M, "verifyReceipt", a -> Scitt.verifyReceipt(bytes(a.get(0)), bytes(a.get(1)), vOpts(a.get(2))));
    }

    @Test void verifyConsistencyProof() throws Exception {
        OracleCases.each(M, "verifyConsistencyProof", a -> Scitt.verifyConsistencyProof(bytes(a.get(0)), (String) a.get(1), (String) a.get(2)));
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("COSE_SIGN1_TAG", Scitt.COSE_SIGN1_TAG);
            m.put("HDR_ALG", Scitt.HDR_ALG);
            m.put("HDR_CONTENT_TYPE", Scitt.HDR_CONTENT_TYPE);
            m.put("HDR_CWT_CLAIMS", Scitt.HDR_CWT_CLAIMS);
            m.put("CWT_ISS", Scitt.CWT_ISS);
            m.put("CWT_SUB", Scitt.CWT_SUB);
            m.put("HDR_VDS", Scitt.HDR_VDS);
            m.put("HDR_VDS_PROOFS", Scitt.HDR_VDS_PROOFS);
            m.put("VDS_RFC9162_SHA256", Scitt.VDS_RFC9162_SHA256);
            m.put("PROOF_TYPE_INCLUSION", Scitt.PROOF_TYPE_INCLUSION);
            m.put("DEFAULT_CONTENT_TYPE", Scitt.DEFAULT_CONTENT_TYPE);
            return m;
        });
    }

    // ---- ES256 (randomized signatures: outcomes only) ----

    @Test void es256SignVerify() throws Exception {
        OracleCases.each(M, "es256SignVerify", a -> {
            Map<String, Object> key = map(a.get(0));
            byte[] st = Scitt.signStatement(a.get(1), new Scitt.SignStatementOpts(CoseAlg.ES256, priv(key), (String) a.get(2)));
            Scitt.CoseSign1 c = Scitt.decodeCoseSign1(st);
            java.math.BigInteger s = new java.math.BigInteger(1, Arrays.copyOfRange(c.signature, 32, 64));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("check", Scitt.checkStatement(st, Scitt.es256PublicKey(Keys.unb64u((String) key.get("x")), Keys.unb64u((String) key.get("y")))).toMap());
            out.put("payload", Scitt.statementPayload(st));
            out.put("lowS", s.compareTo(new java.math.BigInteger("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", 16)) <= 0);
            out.put("protectedBytes", c.protectedBytes);
            return out;
        });
    }

    @Test void es256Receipt() throws Exception {
        OracleCases.each(M, "es256Receipt", a -> {
            Map<String, Object> key = map(a.get(0));
            int n = (int) lng(a.get(1));
            int index = (int) lng(a.get(2));
            PrivateKey edPriv = priv(a.get(3));
            PublicKey edPub = Scitt.ed25519PublicKey(Keys.edFromSeed(Keys.unb64u((String) map(a.get(3)).get("seed"))).pub);
            TransparencyService ts = new TransparencyService(new Scitt.ReceiptSignerOpts(CoseAlg.ES256, priv(key), "ts"));
            List<byte[]> sts = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("i", new Json.Num(Integer.toString(i)));
                sts.add(ts.appendAndReceipt(payload, new Scitt.SignStatementOpts(CoseAlg.EdDSA, edPriv, "iss")).statement);
            }
            PublicKey tsPub = Scitt.es256PublicKey(Keys.unb64u((String) key.get("x")), Keys.unb64u((String) key.get("y")));
            DurableTransparencyService.Registration r = ts.getReceipt(index);
            Scitt.VerifyReceiptOpts o = new Scitt.VerifyReceiptOpts();
            Map<String, Object> out = new LinkedHashMap<>();
            o.verificationKey = tsPub;
            out.put("key", Scitt.verifyReceipt(r.receipt, sts.get(index), o));
            o = new Scitt.VerifyReceiptOpts();
            o.treeRoot = r.root;
            out.put("root", Scitt.verifyReceipt(r.receipt, sts.get(index), o));
            o = new Scitt.VerifyReceiptOpts();
            o.verificationKey = tsPub;
            o.treeRoot = r.root;
            o.statementKey = edPub;
            out.put("both", Scitt.verifyReceipt(r.receipt, sts.get(index), o));
            o = new Scitt.VerifyReceiptOpts();
            o.verificationKey = pub(a.get(4));
            out.put("wrongKey", Scitt.verifyReceipt(r.receipt, sts.get(index), o));
            o = new Scitt.VerifyReceiptOpts();
            o.verificationKey = tsPub;
            byte[] other = (index + 1) % n < sts.size() ? sts.get((index + 1) % n) : new byte[3];
            out.put("otherStatement", Scitt.verifyReceipt(r.receipt, other, o));
            out.put("none", Scitt.verifyReceipt(r.receipt, sts.get(index), new Scitt.VerifyReceiptOpts()));
            return out;
        });
    }

    // ---- services over the log ----

    /** A store that misbehaves the way the oracle's fault spec says. */
    private static final class FaultStore implements ScittLogStore {
        private final ScittLogStore inner = new MemoryScittLogStore();
        private final Map<String, Object> f;

        FaultStore(Map<String, Object> f) { this.f = f; }

        private static boolean at(Object spec, long l, long i) { return spec != null && lng(list(spec).get(0)) == l && lng(list(spec).get(1)) == i; }

        @Override public long size() { return Boolean.TRUE.equals(f.get("negSize")) ? -1 : inner.size(); }

        @Override public byte[] getEntry(long i) { return inner.getEntry(i); }

        @Override public byte[] getNode(long l, long i) {
            if (at(f.get("dropNode"), l, i)) return null;
            if (at(f.get("shortNode"), l, i)) return new byte[31];
            return inner.getNode(l, i);
        }

        @Override public boolean append(long n, byte[] e, List<StoredNode> nodes) { return !Boolean.TRUE.equals(f.get("stale")) && inner.append(n, e, nodes); }
    }

    private static long idx(Object o, boolean durable) {
        if (!safe(o)) {
            if (durable) throw new ScittLogError("out_of_range", "index out of range");
            throw new IllegalArgumentException("index out of range");
        }
        return lng(o);
    }

    @Test void service() throws Exception {
        OracleCases.each(M, "service", a -> {
            Map<String, Object> spec = map(a.get(0));
            boolean durable = "durable".equals(spec.get("kind"));
            Scitt.ReceiptSignerOpts signer = new Scitt.ReceiptSignerOpts(CoseAlg.EdDSA, priv(spec.get("key")), (String) spec.get("issuer"));
            TransparencyService mem = null;
            DurableTransparencyService dur = null;
            if (durable) dur = new DurableTransparencyService(spec.containsKey("storeFault") ? new FaultStore(map(spec.get("storeFault"))) : new MemoryScittLogStore(), signer);
            else mem = new TransparencyService(signer);
            List<Object> res = new ArrayList<>();
            for (Object oo : list(spec.get("ops"))) {
                Map<String, Object> op = map(oo);
                Map<String, Object> r = new LinkedHashMap<>();
                try {
                    Object v;
                    switch ((String) op.get("op")) {
                        case "append": {
                            Scitt.SignStatementOpts so = new Scitt.SignStatementOpts(CoseAlg.EdDSA, priv(spec.get("stmtKey")), "https://issuer.example");
                            if (op.containsKey("subject")) so.subject((String) op.get("subject"));
                            if (op.containsKey("contentType")) so.contentType((String) op.get("contentType"));
                            v = (durable ? dur.appendAndReceipt(op.get("payload"), so) : mem.appendAndReceipt(op.get("payload"), so)).toMap();
                            break;
                        }
                        case "register": v = (durable ? dur.register(bytes(op.get("statement"))) : mem.register(bytes(op.get("statement")))).toMap(); break;
                        case "receipt": v = (durable ? dur.getReceipt(idx(op.get("i"), true)) : mem.getReceipt(idx(op.get("i"), false))).toMap(); break;
                        case "consistency": v = (durable ? dur.consistencyProof(idx(op.get("m"), true)) : mem.consistencyProof(idx(op.get("m"), false))).toMap(); break;
                        case "entry": if (!durable) throw new IllegalStateException("no such method"); v = dur.getEntry(idx(op.get("i"), true)); break;
                        case "snapshot": if (durable) throw new IllegalStateException("no such method"); v = mem.snapshot(); break;
                        case "root": v = durable ? dur.root() : mem.root(); break;
                        case "size": v = durable ? dur.size() : mem.size(); break;
                        default: throw new IllegalStateException("op");
                    }
                    r.put("ok", v);
                } catch (ScittLogError e) {
                    r.put("err", e.code());
                } catch (RuntimeException e) {
                    r.put("err", true);
                }
                res.add(r);
            }
            return res;
        });
    }

    // ---- file store ----

    private int n;

    @Test void fileStoreBytes() throws Exception {
        OracleCases.each(M, "fileStoreBytes", a -> {
            Path p = tmp.resolve("f" + (n++) + ".log");
            try (FileScittLogStore s = FileScittLogStore.open(p)) {
                for (Object oo : list(a.get(0))) {
                    Map<String, Object> op = map(oo);
                    try {
                        List<ScittLogStore.StoredNode> nodes = new ArrayList<>();
                        for (Object no : list(op.get("nodes"))) {
                            List<Object> nl = list(no);
                            nodes.add(new ScittLogStore.StoredNode(lng(nl.get(0)), lng(nl.get(1)), Keys.unb64u((String) nl.get(2))));
                        }
                        s.append(lng(op.get("expected")), bytes(op.get("entry")), nodes);
                    } catch (ScittLogError e) {
                        // a malformed node is refused before anything is written
                    }
                }
            }
            return Files.readAllBytes(p);
        });
    }

    @Test void fileStoreOpen() throws Exception {
        OracleCases.each(M, "fileStoreOpen", a -> {
            Path p = tmp.resolve("o" + (n++) + ".log");
            Files.write(p, bytes(a.get(0)));
            try (FileScittLogStore s = FileScittLogStore.open(p)) {
                List<Object> entries = new ArrayList<>();
                List<Object> nodes0 = new ArrayList<>();
                long size = s.size();
                for (long i = 0; i < size; i++) {
                    entries.add(s.getEntry(i));
                    nodes0.add(s.getNode(0, i));
                }
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("size", size);
                m.put("entries", entries);
                m.put("nodes0", nodes0);
                m.put("after", Files.readAllBytes(p));
                return m;
            }
        });
    }

    @Test void checkScittLogStore() throws Exception {
        OracleCases.each(M, "checkScittLogStore", a -> {
            if ("memory".equals(a.get(0))) return DurableTransparencyService.checkScittLogStore(MemoryScittLogStore::new);
            java.util.List<FileScittLogStore> opened = new java.util.ArrayList<>();
            try {
                return DurableTransparencyService.checkScittLogStore(() -> { FileScittLogStore st = FileScittLogStore.open(tmp.resolve("c" + (n++) + ".log")); opened.add(st); return st; });
            } finally {
                for (FileScittLogStore st : opened) st.close(); // an open file cannot be deleted with the temp directory on Windows
            }
        });
    }

    // ---- plain tests the oracle cannot cover ----

    @Test void fileStoreSurvivesReopen() throws Exception {
        Path p = tmp.resolve("reopen.log");
        Scitt.ReceiptSignerOpts signer = new Scitt.ReceiptSignerOpts(CoseAlg.EdDSA, Scitt.ed25519PrivateKey(new byte[32]), "ts");
        String root;
        try (FileScittLogStore s = FileScittLogStore.open(p)) {
            DurableTransparencyService svc = new DurableTransparencyService(s, signer);
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("a", new Json.Num("1"));
            for (int i = 0; i < 5; i++) svc.appendAndReceipt(payload, new Scitt.SignStatementOpts(CoseAlg.EdDSA, Scitt.ed25519PrivateKey(new byte[32]), "iss"));
            root = svc.root();
        }
        try (FileScittLogStore s = FileScittLogStore.open(p)) {
            DurableTransparencyService svc = new DurableTransparencyService(s, signer);
            assertEquals(5, svc.size());
            assertEquals(root, svc.root());
            assertTrue(Scitt.verifyReceipt(svc.getReceipt(3).receipt, svc.getEntry(3), vOptsRoot(root)));
        }
    }

    private static Scitt.VerifyReceiptOpts vOptsRoot(String root) {
        Scitt.VerifyReceiptOpts o = new Scitt.VerifyReceiptOpts();
        o.treeRoot = root;
        return o;
    }
}
