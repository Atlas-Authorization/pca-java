package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * What you see is what you sign (track K7): a port of the TypeScript {@code approval-render.ts} (render shape, H(R), the approval
 * challenge, the speakable match code) and the pca-actions {@code approval-render.ts} + {@code approval-profiles.ts} (the canonical
 * render of an action, the PSD2 RTS Art. 5 linking view, the batch commitment). A render that cannot be made completely throws
 * {@link Actions.ActionKitError} rather than returning something partial.
 */
public final class Approval {
    private Approval() {}

    public static final String RENDER_DOMAIN = "atlas-pca/approval-render/v1";
    public static final String CHALLENGE_DOMAIN = "atlas-pca/approval-challenge/v1\0";
    public static final String BATCH_DOMAIN = "atlas-pca/approval-batch/v1";
    private static final String ITEM_DOMAIN = "atlas-pca/approval-batch-item/v1";
    private static final String PAYEE_DOMAIN = "atlas-pca/approval-payee/v1";
    private static final int MAX_FIELDS = 64;
    private static final int MAX_DEPTH = 3;
    private static final long MAX_SAFE = 9007199254740991L;

    public static final String[] WORDS = {
        "able", "acid", "aged", "also", "area", "army", "atom", "aunt",
        "away", "baby", "back", "ball", "band", "bank", "base", "bath",
        "bear", "beat", "beef", "bell", "belt", "bend", "bird", "blue",
        "boat", "body", "bold", "bone", "book", "boot", "born", "both",
        "bowl", "bulb", "burn", "bush", "busy", "cafe", "cake", "calm",
        "camp", "card", "care", "cart", "case", "cash", "cast", "cave",
        "cell", "chat", "chef", "chip", "city", "clay", "clip", "club",
        "coal", "coat", "code", "coin", "cold", "cook", "cool", "cope",
        "copy", "cord", "core", "cost", "crew", "crop", "dark", "data",
        "date", "dawn", "deal", "dear", "deck", "deep", "deer", "desk",
        "dial", "dice", "diet", "dish", "dive", "door", "dose", "down",
        "draw", "drop", "drum", "duck", "dust", "duty", "each", "earn",
        "east", "easy", "edge", "echo", "else", "even", "ever", "exit",
        "face", "fact", "fair", "fall", "farm", "fast", "fate", "fern",
        "file", "fill", "film", "find", "fine", "fire", "firm", "fish",
        "five", "flag", "flat", "flow", "foam", "fold", "folk", "food",
        "foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
        "full", "fund", "gain", "game", "gate", "gear", "gift", "girl",
        "glad", "glow", "goat", "gold", "golf", "good", "grab", "gray",
        "grid", "grip", "grow", "gulf", "hair", "half", "hall", "hand",
        "hard", "harp", "hawk", "head", "heat", "help", "herb", "hill",
        "hint", "hold", "hole", "home", "hood", "hook", "hope", "horn",
        "host", "hour", "huge", "hunt", "idea", "inch", "iron", "isle",
        "item", "jade", "jazz", "join", "joke", "jump", "jury", "just",
        "keen", "keep", "kind", "king", "kite", "knee", "knot", "lake",
        "lamp", "land", "lane", "last", "late", "lawn", "lead", "leaf",
        "lean", "left", "lens", "less", "lift", "lime", "line", "link",
        "lion", "list", "live", "load", "loan", "lock", "logo", "long",
        "loop", "lord", "loud", "love", "luck", "lung", "made", "mail",
        "main", "mask", "mass", "mate", "meal", "melt", "menu", "mild",
        "milk", "mind", "mint", "mole", "moon", "more", "moss", "move",
        "much", "nail", "navy", "neat", "neck", "nest", "news", "nice"
    };

    @SuppressWarnings("unchecked") private static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }
    private static Json.Num n(long v) { return IntentJs.ofLong(v); }
    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
    private static boolean digestOk(Object v) { return v instanceof String && Pca.decodeB64uStrict(v, 32) != null; }
    private static boolean bounded(Object v, int max) { return v instanceof String && !((String) v).isEmpty() && ((String) v).getBytes(StandardCharsets.UTF_8).length <= max; }
    private static boolean lone(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++;
            else if (Character.isSurrogate(c)) return true;
        }
        return false;
    }
    private static String closed(Map<String, Object> o, List<String> required, List<String> optional) {
        for (String k : o.keySet()) if (!required.contains(k) && !optional.contains(k)) return "unknown member '" + k + "'";
        for (String k : required) if (!o.containsKey(k)) return "missing member '" + k + "'";
        return null;
    }

    /** Null if {@code r} is a well-formed render (closed members, sorted unique ids, bounded), else the reason. */
    public static String renderShapeError(Object r) {
        if (!(r instanceof Map)) return "render must be an object";
        Map<String, Object> o = M(r);
        String e = closed(o, List.of("v", "kind", "verb", "def_digest", "unreviewed", "fields"), List.of());
        if (e != null) return e;
        if (!(IntentJs.isInt(o.get("v")) && IntentJs.num(o.get("v")) == 1.0) || !"pca-approval-render".equals(o.get("kind"))) return "not a pca-approval-render v1";
        if (!bounded(o.get("verb"), 128)) return "verb must be a bounded string";
        if (!digestOk(o.get("def_digest"))) return "def_digest must be canonical base64url (32 bytes)";
        if (!(o.get("unreviewed") instanceof Boolean)) return "unreviewed must be a boolean";
        if (!(o.get("fields") instanceof List) || ((List<?>) o.get("fields")).size() > MAX_FIELDS) return "fields must be an array of at most " + MAX_FIELDS;
        String prev = null;
        for (Object fo : (List<?>) o.get("fields")) {
            if (!(fo instanceof Map)) return "a field must be an object";
            Map<String, Object> f = M(fo);
            e = closed(f, List.of("id", "class", "value"), List.of("unit"));
            if (e != null) return e;
            if (!bounded(f.get("id"), 192) || !bounded(f.get("class"), 128)) return "field id and class must be bounded strings";
            String id = (String) f.get("id");
            if (prev != null && prev.compareTo(id) >= 0) return "fields must be sorted by id and unique";
            prev = id;
            if (f.containsKey("unit")) {
                if (!(f.get("unit") instanceof Map)) return "unit must be an object";
                Map<String, Object> u = M(f.get("unit"));
                if ("money".equals(u.get("kind"))) {
                    if (closed(u, List.of("kind", "ccy", "exp"), List.of()) != null || !bounded(u.get("ccy"), 16) || !IntentJs.isInt(u.get("exp"))
                        || IntentJs.num(u.get("exp")) < 0 || IntentJs.num(u.get("exp")) > 18) return "a money unit needs ccy and exp";
                } else if (!(u.get("kind") instanceof String) || !List.of("count", "bytes", "duration", "ratio").contains(u.get("kind"))
                    || closed(u, List.of("kind"), List.of()) != null) return "unknown unit";
            }
        }
        return null;
    }

    /** H(R). A malformed render throws (a digest is never made over a shapeless value). */
    public static String renderDigest(Object render) {
        String e = renderShapeError(render);
        if (e != null) throw new IllegalArgumentException("approvalRenderDigest: " + e);
        return Pca.hashCanonical(obj("d", RENDER_DOMAIN, "render", render));
    }

    /** b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values. */
    public static String challenge(Object actionDigest, Object renderDigest) {
        byte[] a = actionDigest instanceof String ? Pca.decodeB64uStrict(actionDigest, 32) : null;
        byte[] r = renderDigest instanceof String ? Pca.decodeB64uStrict(renderDigest, 32) : null;
        if (a == null || r == null) throw new IllegalArgumentException("approvalChallenge: both digests must be canonical 32-byte values");
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            h.update(CHALLENGE_DOMAIN.getBytes(StandardCharsets.UTF_8));
            h.update(a);
            h.update(r);
            return Pca.b64(h.digest());
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public static String bindingWords(Object renderDigest) {
        byte[] r = renderDigest instanceof String ? Pca.decodeB64uStrict(renderDigest, 32) : null;
        if (r == null) throw new IllegalArgumentException("bindingWords: render digest must be a canonical 32-byte value");
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 6; i++) b.append(i == 0 ? "" : "-").append(WORDS[r[i] & 0xff]);
        return b.toString();
    }

    // ---- the render ------------------------------------------------------------------------------------------------------

    private static void flatten(Map<String, Object> out, String prefix, int depth, Object v) {
        if (v instanceof Map && depth < MAX_DEPTH && !((Map<?, ?>) v).isEmpty()) {
            for (Map.Entry<String, Object> e : M(v).entrySet()) {
                if (e.getKey().contains(".")) throw new Actions.ActionKitError("render_bad_params", "the parameter key '" + e.getKey() + "' contains a dot");
                flatten(out, prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey(), depth + 1, e.getValue());
            }
        } else out.put(prefix, v);
    }

    private static boolean leafOk(Object v) {
        if (v instanceof String) return !lone((String) v);
        if (v instanceof Boolean) return true;
        if (v instanceof List) { for (Object x : (List<?>) v) if (!leafOk(x)) return false; return true; }
        return IntentJs.isInt(v);
    }

    private static boolean valueOk(String type, Object v) {
        switch (type) {
            case "integer": case "duration": return IntentJs.isInt(v);
            case "boolean": return v instanceof Boolean;
            case "string": case "date": case "datetime": case "object_ref": return v instanceof String && !lone((String) v);
            case "set": case "array": return leafOk(v) && v instanceof List;
            default: return false;
        }
    }

    /**
     * The canonical approval render of {@code def} for {@code params}. {@code confirmed}: whether the definition carries a valid signed
     * confirmation (the caller decides, as for {@code effective}); an unconfirmed render carries {@code unreviewed: true}.
     */
    public static Map<String, Object> render(Map<String, Object> def, Object params, boolean confirmed) {
        if (!(params instanceof Map)) throw new Actions.ActionKitError("render_bad_params", "params must be an object");
        Map<String, Object> n = Actions.normalize(def);
        Map<String, Object> np = M(n.get("params"));
        Map<String, Object> flat = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : M(params).entrySet()) {
            if (e.getKey().contains(".")) throw new Actions.ActionKitError("render_bad_params", "the parameter key '" + e.getKey() + "' contains a dot");
            flatten(flat, e.getKey(), 1, e.getValue());
        }
        for (String k : flat.keySet()) if (!np.containsKey(k)) throw new Actions.ActionKitError("render_undeclared_param", "'" + k + "' is not a parameter of " + n.get("verb"));
        for (Map.Entry<String, Object> e : np.entrySet())
            if (Boolean.TRUE.equals(M(e.getValue()).get("required")) && !flat.containsKey(e.getKey()))
                throw new Actions.ActionKitError("render_missing_param", "required parameter '" + e.getKey() + "' of " + n.get("verb") + " is missing");
        List<Object> fields = new ArrayList<>();
        for (String id : new TreeMap<>(flat).keySet()) {
            Map<String, Object> p = M(np.get(id));
            if (!valueOk((String) p.get("type"), flat.get(id))) throw new Actions.ActionKitError("render_bad_value", "'" + id + "' is not a " + p.get("type") + " in the canonical domain");
            Map<String, Object> f = obj("id", id, "class", p.containsKey("role") ? p.get("role") : "param", "value", flat.get(id));
            if (p.get("unit") instanceof Map) {
                Map<String, Object> u = M(p.get("unit"));
                if ("money".equals(u.get("kind"))) {
                    Object c = u.get("ccy");
                    Object ccy = c instanceof String ? c : (c instanceof Map ? flat.get(String.valueOf(M(c).get("from"))) : null);
                    if (!(ccy instanceof String) || ((String) ccy).isEmpty()) throw new Actions.ActionKitError("render_unresolved_currency", "the currency of '" + id + "' is not a string");
                    f.put("unit", obj("kind", "money", "ccy", ccy, "exp", u.get("exp")));
                } else f.put("unit", obj("kind", u.get("kind")));
            }
            fields.add(f);
        }
        return obj("v", n(1), "kind", "pca-approval-render", "verb", n_verb(n), "def_digest", Actions.defDigest(def), "unreviewed", !confirmed, "fields", fields);
    }

    private static Object n_verb(Map<String, Object> n) { return n.get("verb"); }

    // ---- PSD2 RTS Art. 5 -------------------------------------------------------------------------------------------------

    private static Actions.ActionKitError unlinkable(String m) { return new Actions.ActionKitError("psd2_unlinkable", m); }

    /** The amount and the payee of a payment render (Art. 5(1)). */
    public static Map<String, Object> psd2Linking(Map<String, Object> r) {
        if (Boolean.TRUE.equals(r.get("unreviewed"))) throw unlinkable("an unreviewed definition cannot be a payment approval");
        List<Map<String, Object>> amts = new ArrayList<>(), payees = new ArrayList<>();
        for (Object fo : (List<?>) r.get("fields")) {
            Map<String, Object> f = M(fo);
            if ("money.amount".equals(f.get("class"))) amts.add(f);
            else if ("party.payee".equals(f.get("class"))) payees.add(f);
        }
        if (amts.size() != 1) throw unlinkable("a payment approval needs exactly one money.amount parameter");
        Map<String, Object> a = amts.get(0);
        if (!(a.get("unit") instanceof Map) || !"money".equals(M(a.get("unit")).get("kind"))) throw unlinkable("the money.amount parameter has no money unit");
        if (!IntentJs.isInt(a.get("value")) || IntentJs.num(a.get("value")) < 0) throw unlinkable("the amount must be a non-negative integer in minor units");
        if (payees.size() != 1 || !(payees.get(0).get("value") instanceof String) || ((String) payees.get(0).get("value")).isEmpty())
            throw unlinkable("a payment approval needs exactly one non-empty party.payee parameter");
        Map<String, Object> u = M(a.get("unit"));
        return obj("amount_minor", a.get("value"), "currency", u.get("ccy"), "exp", u.get("exp"), "payee", payees.get(0).get("value"));
    }

    /** Minor units as the decimal string of the major unit, without floating point. */
    public static String minorToDecimal(long minor, long exp) {
        if (minor < 0 || exp < 0 || exp > 18) throw unlinkable("minor units must be a non-negative safe integer");
        String s = Long.toString(minor);
        if (exp == 0) return s;
        while (s.length() < exp + 1) s = "0" + s;
        return s.substring(0, s.length() - (int) exp) + "." + s.substring(s.length() - (int) exp);
    }

    /** One approval over N payments: per-currency totals, the payee set and every item (Art. 5(3)(b)). Items are {@code {action_digest, render}}. */
    public static Map<String, Object> batch(List<?> items) {
        if (items.isEmpty()) throw unlinkable("a batch needs at least one payment");
        TreeMap<String, long[]> totals = new TreeMap<>();
        TreeMap<String, Boolean> payees = new TreeMap<>();
        List<Object> leaves = new ArrayList<>();
        for (Object io : items) {
            Map<String, Object> it = M(io);
            Map<String, Object> link = psd2Linking(M(it.get("render")));
            String ccy = (String) link.get("currency");
            long exp = IntentJs.lng(link.get("exp")), amt = IntentJs.lng(link.get("amount_minor"));
            long[] t = totals.get(ccy);
            if (t != null && t[0] != exp) throw unlinkable("currency " + ccy + " appears with two exponents");
            long minor = (t == null ? 0 : t[1]) + amt;
            if (minor > MAX_SAFE) throw unlinkable("the batch total exceeds the safe integer range");
            totals.put(ccy, new long[] {exp, minor});
            payees.put((String) link.get("payee"), Boolean.TRUE);
            leaves.add(obj("d", ITEM_DOMAIN, "a", it.get("action_digest"), "r", renderDigest(it.get("render"))));
        }
        List<Object> tl = new ArrayList<>();
        for (Map.Entry<String, long[]> e : totals.entrySet()) tl.add(obj("ccy", e.getKey(), "exp", n(e.getValue()[0]), "minor", n(e.getValue()[1])));
        List<Object> pl = new ArrayList<>();
        for (String p : payees.keySet()) pl.add(obj("d", PAYEE_DOMAIN, "payee", p));
        Map<String, Object> batch = obj("v", n(1), "kind", "pca-approval-batch", "n", n(items.size()), "totals", tl, "payees_root", Pca.merkleRoot(pl), "items_root", Pca.merkleRoot(leaves));
        String rd = Pca.hashCanonical(obj("d", BATCH_DOMAIN, "batch", batch));
        return obj("batch", batch, "action_digest", batch.get("items_root"), "render_digest", rd, "challenge", challenge(batch.get("items_root"), rd), "words", bindingWords(rd));
    }
}
