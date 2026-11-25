package net.atlasauth.pca.intent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.intent.IntentOmega.Outcome;

/**
 * Frame and side-effect constraints: the monitored state of a site, a per-verb write set, and postconditions over the pre- and post-state and
 * the site's effect record. By default intent is frame-closed: a monitored variable outside the write set must not change unless the site's log
 * attributes the change to another actor. A violation is a negative runtime observation (it vetoes the cell). Specs, snapshots and reports are JSON trees.
 */
public final class IntentFrames {
    private IntentFrames() {}

    public static final String FRAME_STATE_DOMAIN = "atlas-pca/intent-frame-state/v1";

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    /** Digest of a state value (site-local: the lenient canonical form; an absent value is null). */
    public static String stateDigest(Object value) {
        Map<String, Object> m = lm();
        m.put("d", FRAME_STATE_DOMAIN);
        m.put("v", value);
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(Json.canonicalize(IntentJs.normalize(m)).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(h);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Snapshot already-read values: variable to {digest, value?}. */
    public static Map<String, Object> snapshotState(Map<String, Object> values, boolean keepValues) {
        Map<String, Object> out = lm();
        for (Map.Entry<String, Object> e : values.entrySet()) {
            Map<String, Object> s = lm();
            s.put("digest", stateDigest(e.getValue()));
            if (keepValues) s.put("value", e.getValue());
            out.put(e.getKey(), s);
        }
        return out;
    }

    /** Read every monitored variable through its reader (sorted by name) and snapshot it: the middleware hook, called before and after the action. */
    public static Map<String, Object> captureState(Map<String, Supplier<Object>> readers, boolean keepValues) {
        TreeMap<String, Supplier<Object>> sorted = new TreeMap<>(Json::compareUtf8);
        sorted.putAll(readers);
        Map<String, Object> values = lm();
        for (Map.Entry<String, Supplier<Object>> e : sorted.entrySet()) values.put(e.getKey(), e.getValue().get());
        return snapshotState(values, keepValues);
    }

    private static Object get(Object root, String path) {
        Object cur = root;
        for (String s : path.split("\\.", -1)) {
            if (cur instanceof Map) {
                if (!((Map<?, ?>) cur).containsKey(s)) return null;
                cur = ((Map<?, ?>) cur).get(s);
            } else if (cur instanceof List && s.matches("0|[1-9][0-9]{0,8}") && Integer.parseInt(s) < ((List<?>) cur).size()) cur = ((List<?>) cur).get(Integer.parseInt(s));
            else return null;
        }
        return cur;
    }

    private static boolean present(Object root, String path) {
        Object cur = root;
        for (String s : path.split("\\.", -1)) {
            if (cur instanceof Map && ((Map<?, ?>) cur).containsKey(s)) cur = ((Map<?, ?>) cur).get(s);
            else if (cur instanceof List && s.matches("0|[1-9][0-9]{0,8}") && Integer.parseInt(s) < ((List<?>) cur).size()) cur = ((List<?>) cur).get(Integer.parseInt(s));
            else return false;
        }
        return true;
    }

    /** W(action): the declared write list, or the parameter-selected list (an unknown parameter value: the default, else empty). */
    public static List<String> writeSetOf(Map<String, Object> spec, Map<String, Object> action) {
        Map<String, Object> writes = IntentOmega.obj(spec.get("writes"));
        Object d = writes.containsKey(action.get("verb")) ? writes.get(action.get("verb")) : null;
        List<String> out = new ArrayList<>();
        if (d == null) return out;
        if (d instanceof List) { for (Object x : (List<?>) d) out.add((String) x); return out; }
        Map<String, Object> dm = IntentOmega.obj(d);
        String param = (String) dm.get("param");
        Object v = get(action.get("params") == null ? lm() : action.get("params"), param.startsWith("action.params.") ? param.substring("action.params.".length()) : param);
        String key = v instanceof String ? (String) v : v instanceof Boolean ? v.toString() : IntentOmega.isNumber(v) ? net.atlasauth.pca.AttestCommon.jsNumString(IntentOmega.dbl(v)) : null;
        Map<String, Object> map = IntentOmega.obj(dm.get("map"));
        Object chosen = key != null && map.containsKey(key) ? map.get(key) : dm.get("default");
        if (chosen != null) for (Object x : IntentOmega.arr(chosen)) out.add((String) x);
        return out;
    }

    private static void envReads(Object c, List<String> out) {
        if (!(c instanceof Map)) return;
        Map<?, ?> m = (Map<?, ?>) c;
        if (m.containsKey("all_of") || m.containsKey("any_of") || m.containsKey("not")) {
            if (m.containsKey("all_of") && m.get("all_of") instanceof List) for (Object x : (List<?>) m.get("all_of")) envReads(x, out);
            else if (m.containsKey("any_of") && m.get("any_of") instanceof List) for (Object x : (List<?>) m.get("any_of")) envReads(x, out);
            else if (m.containsKey("not")) envReads(m.get("not"), out);
            return;
        }
        if (m.get("field") instanceof String) {
            if (((String) m.get("field")).startsWith("env.")) out.add((String) m.get("field"));
            if (m.get("ref") instanceof String && ((String) m.get("ref")).startsWith("env.")) out.add((String) m.get("ref"));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nest(Map<String, Object> s) {
        Map<String, Object> root = lm();
        for (Map.Entry<String, Object> e : s.entrySet()) {
            Map<String, Object> v = IntentOmega.obj(e.getValue());
            if (!v.containsKey("value")) continue;
            String[] segs = e.getKey().split("\\.", -1);
            Map<String, Object> cur = root;
            for (int i = 0; i < segs.length - 1; i++) {
                if (!(cur.get(segs[i]) instanceof Map)) cur.put(segs[i], lm());
                cur = (Map<String, Object>) cur.get(segs[i]);
            }
            cur.put(segs[segs.length - 1], v.get("value"));
        }
        return root;
    }

    private static List<String> uniqSorted(List<String> xs) {
        List<String> l = new ArrayList<>(new LinkedHashSet<>(xs));
        l.sort(Json::compareUtf8);
        return l;
    }

    /**
     * Check one executed action: the frame condition over the monitored state outside its write set and the verb's postconditions. {@code opts}: effect?,
     * attributions? ([{var, actor}]), self?. Returns {status, outOfFrame, attributed, postViolated, missing, unmonitored}; never throws.
     */
    public static Map<String, Object> checkFrame(Object specO, Object actionO, Object preO, Object postO, Map<String, Object> opts) {
        List<String> outOfFrame = new ArrayList<>(), attributed = new ArrayList<>(), postViolated = new ArrayList<>(), missing = new ArrayList<>();
        boolean unmonitored = false;
        try {
            if (!(specO instanceof Map) || !(((Map<?, ?>) specO).get("state") instanceof List) || !(actionO instanceof Map) || !(preO instanceof Map) || !(postO instanceof Map)) {
                throw new IllegalArgumentException("spec, action, pre and post must be objects (spec.state an array)");
            }
            Map<String, Object> spec = IntentOmega.obj(specO), action = IntentOmega.obj(actionO), pre = IntentOmega.obj(preO), post = IntentOmega.obj(postO);
            List<Object> state = IntentOmega.arr(spec.get("state"));
            unmonitored = state.isEmpty();
            Set<String> w = new LinkedHashSet<>(writeSetOf(spec, action));
            List<String> sortedState = new ArrayList<>();
            for (Object v : state) sortedState.add((String) v);
            sortedState.sort(Json::compareUtf8);
            List<Object> attrs = opts != null && opts.get("attributions") != null ? IntentOmega.arr(opts.get("attributions")) : new ArrayList<>();
            Object self = opts == null ? null : opts.get("self");
            for (String v : sortedState) {
                if (w.contains(v)) continue;
                Object a = pre.get(v), b = post.get(v);
                if (a == null || b == null) { missing.add(v); continue; }
                if (Objects.equals(IntentOmega.obj(a).get("digest"), IntentOmega.obj(b).get("digest"))) continue;
                boolean other = false;
                for (Object xo : attrs) {
                    Map<String, Object> x = IntentOmega.obj(xo);
                    if (Objects.equals(x.get("var"), v) && !Objects.equals(x.get("actor"), self)) other = true;
                }
                (other ? attributed : outOfFrame).add(v);
            }
            Map<String, Object> env = lm();
            env.put("pre", nest(pre));
            env.put("post", nest(post));
            env.put("effect", opts != null && opts.get("effect") != null ? opts.get("effect") : lm());
            Map<String, Object> act = lm();
            act.put("verb", action.get("verb"));
            act.put("resource", action.get("resource"));
            act.put("params", action.get("params") == null ? lm() : action.get("params"));
            Map<String, Object> ctx = lm();
            ctx.put("action", act);
            ctx.put("env", env);
            Map<String, Object> envRoot = lm();
            envRoot.put("env", env);
            List<Object> posts = spec.get("post") == null ? new ArrayList<>() : IntentOmega.arr(spec.get("post"));
            for (Object pco : posts) {
                Map<String, Object> pc = IntentOmega.obj(pco);
                if (!Objects.equals(pc.get("verb"), action.get("verb"))) continue;
                boolean pending = false;
                List<Object> deltas = pc.get("deltas") == null ? new ArrayList<>() : IntentOmega.arr(pc.get("deltas"));
                for (Object dO : deltas) {
                    Map<String, Object> d = IntentOmega.obj(dO);
                    Object x = get(env.get("pre"), (String) d.get("path")), y = get(env.get("post"), (String) d.get("path"));
                    if (!IntentOmega.isNumber(x) || !IntentOmega.isNumber(y)) {
                        missing.add(pc.get("id") + ":" + d.get("path"));
                        pending = true;
                    } else if (IntentOmega.dbl(y) != IntentOmega.dbl(x) + IntentOmega.dbl(d.get("by"))) {
                        postViolated.add((String) pc.get("id"));
                        pending = true;
                        break;
                    }
                }
                if (pending) continue;
                List<String> reads = new ArrayList<>();
                List<Object> where = pc.get("where") == null ? new ArrayList<>() : IntentOmega.arr(pc.get("where"));
                for (Object c : where) envReads(c, reads);
                List<String> absent = new ArrayList<>();
                for (String r : reads) if (!present(envRoot, r)) absent.add(r);
                if (!absent.isEmpty()) {
                    for (String r : absent) missing.add(pc.get("id") + ":" + r);
                    continue;
                }
                if (!where.isEmpty()) {
                    Map<String, Object> pred = lm();
                    pred.put("verb", action.get("verb"));
                    pred.put("where", where);
                    if (!Predicates.evaluatePredicates(List.of(pred), ctx)) postViolated.add((String) pc.get("id"));
                }
            }
        } catch (RuntimeException e) {
            missing.add("error: " + (e instanceof IllegalArgumentException && String.valueOf(e.getMessage()).startsWith("spec, action") ? e.getMessage() : "error"));
        }
        List<String> miss = uniqSorted(missing);
        List<String> pv = uniqSorted(postViolated);
        Map<String, Object> rep = lm();
        rep.put("status", !outOfFrame.isEmpty() || !pv.isEmpty() ? "violated" : !miss.isEmpty() ? "pending" : "ok");
        rep.put("outOfFrame", new ArrayList<Object>(outOfFrame));
        rep.put("attributed", new ArrayList<Object>(attributed));
        rep.put("postViolated", new ArrayList<Object>(pv));
        rep.put("missing", new ArrayList<Object>(miss));
        rep.put("unmonitored", unmonitored);
        return rep;
    }

    /** Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell; ok and pending change nothing. */
    public static Map<String, Object> applyFrameReport(IntentLearner l, Outcome o, Object report) {
        Map<String, Object> r = lm();
        if (!(report instanceof Map) || !"violated".equals(((Map<?, ?>) report).get("status"))) return r;
        r.put("signal", "postcondition-violation");
        r.put("divergence", IntentMapKit.applyDivergence(l, o, 0));
        return r;
    }
}
