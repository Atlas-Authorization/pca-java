package net.atlasauth.pca.dataflow;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.EvidenceBridge;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import java.util.Objects;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Detector adapters: vendor guardrail responses to signed, tighten-only receipts. The gateway that calls a detector signs what it
 * saw; the verifier pins the gateway key and folds the receipts, where {@code suspicious} can only lower a decision and
 * {@code no_finding} is exactly no receipt. The adapters are deliberately one-sided: a response is {@code no_finding} only when it
 * is well-formed AND says nothing was detected; anything malformed, unexpected or ambiguous becomes {@code suspicious} with the
 * category {@code detector_error}. Responses are JSON trees. The adapter context is a Map: {@code detector}, {@code version},
 * {@code content} (any JSON), {@code secretKey} (the gateway's 32-byte Ed25519 seed, a {@code byte[]}), {@code now} (epoch ms),
 * and the optional {@code session} / {@code calibration_ref}. Receipts are signed with Ed25519.
 */
public final class Detectors {
    private Detectors() {}

    public static final String DETECTOR_RECEIPT_DOMAIN = "atlas-pca/detector-receipt/v1\0";
    public static final String DETECTOR_RECEIPT_REF_DOMAIN = "atlas-pca/detector-receipt-ref/v1";
    public static final List<String> DETECTOR_VERDICTS = Collections.unmodifiableList(java.util.Arrays.asList("suspicious", "no_finding"));
    /** The most receipts a verifier folds in one call. */
    public static final int MAX_DETECTOR_RECEIPTS = 32;
    private static final Pattern CAT_RE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern NON_ALNUM = Pattern.compile("[^a-z0-9]+");
    private static final Pattern EDGE_UNDERSCORES = Pattern.compile("^_+|_+$");
    private static final Pattern LEADING_DIGIT = Pattern.compile("^([0-9])");

    /** The digest a receipt binds: b64u(sha256(strictCanonical({d, content}))). */
    public static String detectorInputDigest(Object content) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/detector-input/v1");
        m.put("content", content);
        return Pca.hashCanonical(m);
    }

    /** Vendor category text to a receipt category id (lowercase, non-alphanumerics to {@code _}); unusable text becomes {@code other}. */
    public static String categoryId(Object s) {
        if (!(s instanceof String)) return "other";
        String c = ((String) s).toLowerCase(java.util.Locale.ROOT);
        c = NON_ALNUM.matcher(c).replaceAll("_");
        c = EDGE_UNDERSCORES.matcher(c).replaceAll("");
        c = LEADING_DIGIT.matcher(c).replaceAll("c_$1");
        if (c.length() > 64) c = c.substring(0, 64);
        return CAT_RE.matcher(c).matches() ? c : "other";
    }

    private static boolean isObj(Object v) { return v instanceof Map; }

    private static int u8len(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80) n += 1;
            else if (c < 0x800) n += 2;
            else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { n += 4; i++; }
            else n += 3; // BMP, or a lone surrogate (U+FFFD in UTF-8)
        }
        return n;
    }

    private static boolean boundedString(Object v, int max) { return v instanceof String && !((String) v).isEmpty() && u8len((String) v) <= max; }

    /** Null when the receipt is well-formed (the shape the gateway signs). */
    public static String receiptShapeError(Map<String, Object> r) {
        List<String> required = List.of("v", "kind", "detector", "version", "input_digest", "verdict", "categories", "iat", "sig");
        List<String> optional = List.of("session", "calibration_ref", "alg", "pq_pk", "pq_sig");
        for (String k : r.keySet()) if (!required.contains(k) && !optional.contains(k)) return "unknown member 'receipt." + k + "'";
        for (String k : required) if (!r.containsKey(k)) return "missing member 'receipt." + k + "'";
        if (!JsVal.isNumber(r.get("v")) || JsVal.num(r.get("v")) != 1.0 || !"pca-detector-receipt".equals(r.get("kind"))) return "not a pca-detector-receipt v1";
        if (!(r.get("detector") instanceof String) || !CAT_RE.matcher((String) r.get("detector")).matches()) return "detector id is malformed";
        if (!boundedString(r.get("version"), 64)) return "version must be 1..64 bytes";
        if (Pca.decodeB64uStrict(r.get("input_digest"), 32) == null) return "input_digest must be a b64u 32-byte digest";
        if (!"suspicious".equals(r.get("verdict")) && !"no_finding".equals(r.get("verdict"))) return "verdict must be 'suspicious' or 'no_finding'";
        Object c = r.get("categories");
        if (!(c instanceof List) || ((List<?>) c).size() > 8) return "categories must be 0..8 ids";
        List<?> cl = (List<?>) c;
        for (Object x : cl) if (!(x instanceof String) || !CAT_RE.matcher((String) x).matches()) return "categories must be 0..8 ids";
        for (int i = 1; i < cl.size(); i++) if (!(((String) cl.get(i - 1)).compareTo((String) cl.get(i)) < 0)) return "categories must be sorted and distinct";
        if ("no_finding".equals(r.get("verdict")) && !cl.isEmpty()) return "a no_finding receipt carries no categories";
        Object iat = r.get("iat");
        if (!(JsVal.isSafeInteger(iat) && JsVal.num(iat) >= 0 && !(JsVal.num(iat) == 0 && 1 / JsVal.num(iat) < 0))) return "iat must be a non-negative integer";
        if (r.containsKey("session") && Pca.decodeB64uStrict(r.get("session"), 32) == null) return "session must be a b64u 32-byte id";
        if (r.containsKey("calibration_ref") && !boundedString(r.get("calibration_ref"), 256)) return "calibration_ref must be 1..256 bytes";
        if (!(r.get("sig") instanceof String)) return "sig must be a string";
        return EvidenceBridge.artifactSuiteError(r);
    }

    private static Map<String, Object> receipt(Map<String, Object> ctx, boolean suspicious, Set<String> categories) {
        List<Object> cats = new ArrayList<>();
        if (suspicious) {
            List<String> sorted = new ArrayList<>(new LinkedHashSet<>(categories));
            Collections.sort(sorted);
            cats.addAll(sorted.subList(0, Math.min(8, sorted.size())));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", new Json.Num("1"));
        body.put("kind", "pca-detector-receipt");
        body.put("detector", ctx.get("detector"));
        body.put("version", ctx.get("version"));
        body.put("input_digest", detectorInputDigest(ctx.get("content")));
        body.put("verdict", suspicious ? "suspicious" : "no_finding");
        body.put("categories", cats);
        body.put("iat", ctx.get("now"));
        if (ctx.containsKey("session")) body.put("session", ctx.get("session"));
        if (ctx.containsKey("calibration_ref")) body.put("calibration_ref", ctx.get("calibration_ref"));
        byte[] seed = (byte[]) ctx.get("secretKey");
        Map<String, Object> signed = Issue.signArtifact(DETECTOR_RECEIPT_DOMAIN, body, Keys.ed25519(Keys.edFromSeed(seed)));
        String e = receiptShapeError(signed);
        if (e != null) throw new IllegalArgumentException("signDetectorReceipt: " + e);
        return signed;
    }

    private static Map<String, Object> errorReceipt(Map<String, Object> ctx) {
        return receipt(ctx, true, new LinkedHashSet<>(List.of("detector_error")));
    }

    /** Lakera Guard v2 {@code /guard} response. */
    public static Map<String, Object> lakeraReceipt(Object response, Map<String, Object> ctx) {
        if (!isObj(response) || !(((Map<?, ?>) response).get("flagged") instanceof Boolean)) return errorReceipt(ctx);
        Map<?, ?> r = (Map<?, ?>) response;
        Set<String> cats = new LinkedHashSet<>();
        if (r.containsKey("breakdown")) {
            if (!(r.get("breakdown") instanceof List)) return errorReceipt(ctx);
            for (Object b : (List<?>) r.get("breakdown")) {
                if (!isObj(b) || !(((Map<?, ?>) b).get("detected") instanceof Boolean)) return errorReceipt(ctx);
                if ((Boolean) ((Map<?, ?>) b).get("detected")) cats.add(categoryId(((Map<?, ?>) b).get("detector_type")));
            }
        }
        boolean suspicious = (Boolean) r.get("flagged") || !cats.isEmpty();
        if (suspicious && cats.isEmpty()) cats.add("flagged");
        return receipt(ctx, suspicious, cats);
    }

    /** Prompt Security {@code /api/protect} response (shape UNVERIFIED against the vendor; both open-source integration shapes accepted). */
    public static Map<String, Object> promptSecurityReceipt(Object response, Map<String, Object> ctx) {
        Object r = isObj(response) && isObj(((Map<?, ?>) response).get("result")) ? ((Map<?, ?>) response).get("result") : null;
        if (r == null) return errorReceipt(ctx);
        Map<?, ?> rm = (Map<?, ?>) r;
        boolean hasP = rm.containsKey("prompt");
        Object p = rm.get("prompt");
        if (hasP && !isObj(p)) return errorReceipt(ctx);
        List<Object> actions = new ArrayList<>();
        if (rm.containsKey("action")) actions.add(rm.get("action"));
        if (isObj(p) && ((Map<?, ?>) p).containsKey("action")) actions.add(((Map<?, ?>) p).get("action"));
        if (actions.isEmpty()) return errorReceipt(ctx);
        for (Object a : actions) if (!(a instanceof String)) return errorReceipt(ctx);
        boolean hasV = isObj(p) && ((Map<?, ?>) p).containsKey("violations");
        Object violations = hasV ? ((Map<?, ?>) p).get("violations") : null;
        if (hasV && !(violations instanceof List)) return errorReceipt(ctx);
        Set<String> cats = new LinkedHashSet<>();
        if (hasV) for (Object v : (List<?>) violations) cats.add(categoryId(v));
        if (actions.contains("block")) cats.add("blocked");
        if (actions.contains("modify")) cats.add("modified");
        return receipt(ctx, !cats.isEmpty(), cats);
    }

    /** Any detector that answers {@code {flagged, categories?}}. */
    public static Map<String, Object> genericReceipt(Object response, Map<String, Object> ctx) {
        if (!isObj(response) || !(((Map<?, ?>) response).get("flagged") instanceof Boolean)) return errorReceipt(ctx);
        Map<?, ?> r = (Map<?, ?>) response;
        boolean hasC = r.containsKey("categories");
        if (hasC && !(r.get("categories") instanceof List)) return errorReceipt(ctx);
        Set<String> cats = new LinkedHashSet<>();
        if (hasC) for (Object c : (List<?>) r.get("categories")) cats.add(categoryId(c));
        boolean flagged = (Boolean) r.get("flagged");
        if (!flagged && !cats.isEmpty()) return errorReceipt(ctx); // categories on a clean answer: ambiguous
        if (flagged && cats.isEmpty()) cats.add("flagged");
        return receipt(ctx, flagged, cats);
    }


    /** Content address of a receipt (signature included). */
    public static String detectorReceiptRef(Object r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", DETECTOR_RECEIPT_REF_DOMAIN);
        m.put("receipt", r);
        return Pca.hashCanonical(m);
    }

    /** Null when the receipt is well-formed. */
    public static String detectorReceiptShapeError(Object r) {
        return r instanceof Map ? receiptShapeError(asMap(r)) : "receipt must be an object";
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return (Map<String, Object>) o; }

    private static boolean closed(Map<?, ?> m, List<String> required, List<String> optional) {
        for (Object k : m.keySet()) if (!required.contains(k) && !optional.contains(k)) return false;
        for (String k : required) if (!m.containsKey(k)) return false;
        return true;
    }

    private static boolean catId(Object o) { return o instanceof String && CAT_RE.matcher((String) o).matches(); }

    private static boolean safeInt(Object o) { return JsVal.isSafeInteger(o); }

    /**
     * Null when the detector policy {@code {detectors: [{id, keys (1..8 pins {pk, pq_pk?}), on_suspicious, max_age_ms, categories?}]}}
     * is well-formed (at most 16 detectors, distinct ids other than {@code invalid}).
     */
    public static String detectorPolicyError(Object p) {
        if (!(p instanceof Map) || !closed((Map<?, ?>) p, List.of("detectors"), List.of())) return "policy must be {detectors}";
        Object ds = ((Map<?, ?>) p).get("detectors");
        if (!(ds instanceof List) || ((List<?>) ds).size() > 16) return "detectors must hold at most 16 entries";
        Set<String> ids = new LinkedHashSet<>();
        for (Object d0 : (List<?>) ds) {
            if (!(d0 instanceof Map) || !closed((Map<?, ?>) d0, List.of("id", "keys", "on_suspicious", "max_age_ms"), List.of("categories"))) return "detector entry is malformed";
            Map<?, ?> d = (Map<?, ?>) d0;
            Object id = d.get("id");
            if (!catId(id) || "invalid".equals(id) || ids.contains(id)) return "detector ids must be distinct ids other than \"invalid\"";
            ids.add((String) id);
            Object keys = d.get("keys");
            boolean keysOk = keys instanceof List && ((List<?>) keys).size() >= 1 && ((List<?>) keys).size() <= 8;
            if (keysOk) for (Object k : (List<?>) keys) {
                if (!(k instanceof Map) || !(((Map<?, ?>) k).get("pk") instanceof String) || (((Map<?, ?>) k).containsKey("pq_pk") && !(((Map<?, ?>) k).get("pq_pk") instanceof String))) { keysOk = false; break; }
            }
            if (!keysOk) return "detector '" + id + "': keys must hold 1..8 pins";
            if (!"escalate".equals(d.get("on_suspicious")) && !"deny".equals(d.get("on_suspicious"))) return "detector '" + id + "': on_suspicious must be escalate or deny";
            if (d.containsKey("categories")) {
                Object cs = d.get("categories");
                boolean ok = cs instanceof List && !((List<?>) cs).isEmpty();
                if (ok) for (Object c : (List<?>) cs) if (!catId(c)) { ok = false; break; }
                if (!ok) return "detector '" + id + "': categories must be 1+ ids";
            }
            Object age = d.get("max_age_ms");
            if (!(safeInt(age) && JsVal.num(age) >= 1 && JsVal.num(age) <= 86_400_000)) return "detector '" + id + "': max_age_ms must be 1..86400000";
        }
        return null;
    }

    private static int rankOf(String s) { return "ok".equals(s) ? 2 : "escalate".equals(s) ? 1 : 0; }

    private static String receiptProblem(Object r, Map<String, Object> policy, List<?> digests, Object session, Object now) {
        String se = detectorReceiptShapeError(r);
        if (se != null) return "malformed: " + se;
        Map<String, Object> rc = asMap(r);
        Map<String, Object> d = null;
        for (Object x : (List<?>) policy.get("detectors")) if (asMap(x).get("id").equals(rc.get("detector"))) { d = asMap(x); break; }
        if (d == null) return "undeclared detector '" + rc.get("detector") + "'";
        boolean signed = false;
        for (Object k : (List<?>) d.get("keys")) {
            if (EvidenceBridge.verifyArtifactSig(DETECTOR_RECEIPT_DOMAIN, rc, asMap(k).get("pk"), asMap(k).get("pq_pk"))) { signed = true; break; }
        }
        if (!signed) return "detector '" + d.get("id") + "': no pinned key signed it";
        if (!digests.contains(rc.get("input_digest"))) return "detector '" + d.get("id") + "': the receipt is about other content";
        if (rc.containsKey("session") && !Objects.equals(rc.get("session"), session)) return "detector '" + d.get("id") + "': bound to another session";
        double iat = JsVal.num(rc.get("iat")), n = JsVal.num(now);
        if (iat > n) return "detector '" + d.get("id") + "': from the future";
        if (n - iat > JsVal.num(d.get("max_age_ms"))) return "detector '" + d.get("id") + "': stale";
        return null;
    }

    private static Map<String, Object> rejection(long index, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", index);
        m.put("reason", reason);
        return m;
    }

    /**
     * The tighten-only fold of detector receipts. Total. {@code input} is {@code {receipts?, policy, input_digests, session?, now}}. A malformed
     * policy is {@code deny}; an invalid receipt (shape, undeclared detector, no pinned key signed it, other content, other session, from the
     * future, stale) lowers the signal to {@code escalate}; a valid {@code suspicious} receipt with an acting category lowers it to the
     * detector's {@code on_suspicious}; a valid {@code no_finding} changes nothing. Returns {@code {signal, env: {detect: {...}}, flagged, rejected}}.
     */
    public static Map<String, Object> detectorSignal(Map<String, Object> input) {
        Set<String> flagged = new LinkedHashSet<>();
        List<Object> rejected = new ArrayList<>();
        String[] signal = {"ok"};
        java.util.function.Consumer<String> lower = s -> { if (rankOf(s) < rankOf(signal[0])) signal[0] = s; };
        Map<String, Object> env = new LinkedHashMap<>();
        try {
            Object policy = input == null ? null : input.get("policy");
            String pe = detectorPolicyError(policy);
            if (pe != null) {
                Map<String, Object> detect = new LinkedHashMap<>();
                detect.put("invalid", 0L);
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("signal", "deny");
                out.put("env", new LinkedHashMap<String, Object>(Map.of("detect", detect)));
                out.put("flagged", new ArrayList<>());
                out.put("rejected", new ArrayList<Object>(List.of(rejection(-1, "policy: " + pe))));
                return out;
            }
            Map<String, Object> pol = asMap(policy);
            for (Object d : (List<?>) pol.get("detectors")) env.put((String) asMap(d).get("id"), Boolean.FALSE);
            Object receipts = input.get("receipts") == null ? new ArrayList<>() : input.get("receipts");
            List<?> digests = input.get("input_digests") instanceof List ? (List<?>) input.get("input_digests") : new ArrayList<>();
            Object now = input.get("now");
            if (!(receipts instanceof List) || ((List<?>) receipts).size() > MAX_DETECTOR_RECEIPTS || !safeInt(now)) {
                lower.accept("escalate");
                rejected.add(rejection(-1, "receipt list or clock malformed"));
            } else {
                int index = 0;
                for (Object r : (List<?>) receipts) {
                    String why = receiptProblem(r, pol, digests, input.get("session"), now);
                    if (why != null) {
                        rejected.add(rejection(index++, why));
                        lower.accept("escalate");
                        continue;
                    }
                    index++;
                    Map<String, Object> rc = asMap(r);
                    if (!"suspicious".equals(rc.get("verdict"))) continue;
                    Map<String, Object> d = null;
                    for (Object x : (List<?>) pol.get("detectors")) if (asMap(x).get("id").equals(rc.get("detector"))) { d = asMap(x); break; }
                    List<?> rcats = (List<?>) rc.get("categories");
                    if (d.containsKey("categories") && !rcats.isEmpty()) {
                        boolean any = false;
                        for (Object c : rcats) if (((List<?>) d.get("categories")).contains(c)) { any = true; break; }
                        if (!any) continue;
                    }
                    flagged.add((String) d.get("id"));
                    env.put((String) d.get("id"), Boolean.TRUE);
                    lower.accept((String) d.get("on_suspicious"));
                }
            }
        } catch (RuntimeException e) {
            lower.accept("deny");
            rejected.add(rejection(-1, "evaluation error (fail closed): " + (e.getMessage() != null ? e.getMessage() : "unknown")));
        }
        env.put("invalid", (long) rejected.size());
        List<String> sortedFlagged = new ArrayList<>(flagged);
        Collections.sort(sortedFlagged);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("signal", signal[0]);
        Map<String, Object> envOut = new LinkedHashMap<>();
        envOut.put("detect", env);
        out.put("env", envOut);
        out.put("flagged", new ArrayList<Object>(sortedFlagged));
        out.put("rejected", rejected);
        return out;
    }
}
