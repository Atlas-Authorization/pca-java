package net.atlasauth.pca.sandbox;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Runtime classes and the append-only hash chain of use receipts: every handle use and every egress decision, refusals
 * included. Receipts are JSON objects (maps), byte-identical to the reference's.
 */
public final class Receipts {
    private Receipts() {}

    /** Runtime classes, weakest first. The class is a claim by the host operator, recorded in every receipt. */
    public static final List<String> RUNTIME_CLASSES = Collections.unmodifiableList(Arrays.asList("none", "os_confined", "egress_default_deny", "wasi_no_ambient"));

    public static final String GENESIS = "genesis";

    /** True only when both names are known and {@code attested} is at least {@code required}. An unknown name never satisfies. */
    public static boolean satisfiesRuntimeClass(Object attested, Object required) {
        int a = attested instanceof String ? RUNTIME_CLASSES.indexOf(attested) : -1;
        int r = required instanceof String ? RUNTIME_CLASSES.indexOf(required) : -1;
        return a >= 0 && r >= 0 && a >= r;
    }

    /** Append-only hash chain of receipts. */
    public static final class ReceiptLog {
        private final List<Map<String, Object>> entries = new ArrayList<>();
        private final Supplier<Object> now;
        private final UnaryOperator<String> sign;

        /** {@code now}: the host clock as a JSON number (default: epoch ms); {@code sign}: optional host signature over a digest. */
        public ReceiptLog(Supplier<Object> now, UnaryOperator<String> sign) {
            this.now = now != null ? now : () -> Long.valueOf(System.currentTimeMillis());
            this.sign = sign;
        }

        public ReceiptLog() { this(null, null); }

        public List<Map<String, Object>> entries() { return Collections.unmodifiableList(entries); }

        /** Append a receipt; {@code body} carries kind, subject, outcome and reason. A throwing clock or signer appends nothing. */
        public synchronized Map<String, Object> append(String runtimeClass, Map<String, Object> body) {
            Map<String, Object> unsigned = new LinkedHashMap<>();
            unsigned.put("v", 1L);
            unsigned.put("seq", (long) entries.size());
            unsigned.put("prev", entries.isEmpty() ? GENESIS : entries.get(entries.size() - 1).get("digest"));
            unsigned.put("at", now.get());
            unsigned.put("runtime_class", runtimeClass);
            unsigned.putAll(body);
            String digest = Pca.hashCanonical(unsigned);
            Map<String, Object> r = new LinkedHashMap<>(unsigned);
            r.put("digest", digest);
            if (sign != null) r.put("sig", sign.apply(digest));
            entries.add(r);
            return r;
        }
    }

    /**
     * Recompute the chain. Fails on a bad digest, a broken link, a gap, a reorder, or (with {@code verifySig}) a bad signature.
     * Returns {@code {ok:true}} or {@code {ok:false, at, reason}}. A receipt list that is not a list, or a null receipt, throws
     * (as the reference does).
     */
    public static Map<String, Object> verifyReceiptChain(Object receipts, BiPredicate<String, String> verifySig) {
        if (!(receipts instanceof List)) throw new JsVal.TypeError("receipts is not iterable");
        String prev = GENESIS;
        List<?> list = (List<?>) receipts;
        for (int i = 0; i < list.size(); i++) {
            Object r = list.get(i);
            Object v = JsVal.member(r, "v");
            Double vn = JsVal.num(v);
            Double sn = JsVal.num(JsVal.opt(r, "seq"));
            if (vn == null || vn != 1.0 || sn == null || sn != (double) i) return fail(i, "bad_seq");
            if (!prev.equals(JsVal.opt(r, "prev"))) return fail(i, "broken_link");
            Map<String, Object> rest = new LinkedHashMap<>();
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) r;
            for (Map.Entry<String, Object> e : m.entrySet()) if (!e.getKey().equals("digest") && !e.getKey().equals("sig")) rest.put(e.getKey(), e.getValue());
            Object digest = m.get("digest");
            if (!Pca.hashCanonical(rest).equals(digest)) return fail(i, "bad_digest");
            Object sig = m.get("sig");
            if (verifySig != null && (!(sig instanceof String) || !verifySig.test((String) digest, (String) sig))) return fail(i, "bad_sig");
            prev = (String) digest;
        }
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", Boolean.TRUE);
        return ok;
    }

    private static Map<String, Object> fail(int at, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.FALSE);
        m.put("at", (long) at);
        m.put("reason", reason);
        return m;
    }
}
