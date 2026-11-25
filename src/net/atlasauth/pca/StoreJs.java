package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small JSON-tree helpers shared by the durable store classes (copying, number boxing). */
public final class StoreJs {
    private StoreJs() {}

    /** A deep copy of a JSON tree (Map, List, scalars). Stores never hand out or keep a caller's mutable structure. */
    @SuppressWarnings("unchecked")
    public static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), deepCopy(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(deepCopy(x));
            return out;
        }
        return v;
    }

    /** The JSON number for a long (a safe integer prints as is). */
    public static Json.Num num(long v) { return new Json.Num(Long.toString(v)); }

    /** The JSON number for a double, printed as JavaScript prints it. */
    public static Json.Num num(double v) { return new Json.Num(AttestCommon.jsNumString(v)); }

    /** The double of a JSON number, or null. */
    public static Double dbl(Object v) { return IntentJs.num(v); }

    /** True for a JavaScript safe integer that is not -0. */
    public static boolean isInt(Object v) { return IntentJs.isInt(v); }

    /** The long of a safe integer (call after {@link #isInt}). */
    public static long lng(Object v) { return IntentJs.lng(v); }

    /** True when {@code v} is a finite JSON number. */
    public static boolean isFinite(Object v) { return IntentJs.isFinite(v); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object v) { return v instanceof Map ? (Map<String, Object>) v : null; }

    /** base64url(sha256(lenient canonical JSON)): the reference's lenient content hash. */
    public static String hashLenient(Object v) { return Pca.b64(Pca.sha(Json.canonicalize(v).getBytes(java.nio.charset.StandardCharsets.UTF_8))); }

    public static boolean jsonEq(Object a, Object b) { return hashLenient(a).equals(hashLenient(b)); }
}
