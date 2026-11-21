package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** A constitution's stateless invariants in analyzable (veto) form. */
public final class Constitution {
    private Constitution() {}

    private static void put(Map<String, Object> to, String k, Object from, String fk) {
        if (Js.has(from, fk)) to.put(k, Js.get(from, fk));
    }

    /**
     * Turn a constitution into analyzer vetoes: {@code {vetoes, unmodeled}}. {@code never} / {@code never_unless} /
     * {@code require_approval_over} become vetoes; {@code cap} / {@code rate} are bounded by maxExposure instead, and every other kind
     * needs history, so both are listed in {@code unmodeled}.
     */
    public static Map<String, Object> vetoesFromConstitution(Object c) {
        List<Object> vetoes = new ArrayList<>();
        List<Object> unmodeled = new ArrayList<>();
        Object invs = Js.get(c, "invariants");
        if (invs instanceof List) {
            for (Object inv : (List<?>) invs) {
                if (inv == null) throw new IllegalArgumentException("invariant is null");
                Object kind = Js.get(inv, "kind");
                String k = kind instanceof String ? (String) kind : "";
                switch (k) {
                    case "never": {
                        Map<String, Object> v = Js.obj();
                        put(v, "id", inv, "id");
                        v.put("kind", "deny");
                        put(v, "when", inv, "when");
                        vetoes.add(v);
                        break;
                    }
                    case "never_unless": {
                        Map<String, Object> v = Js.obj();
                        put(v, "id", inv, "id");
                        v.put("kind", "deny");
                        put(v, "when", inv, "when");
                        put(v, "unless", inv, "unless");
                        vetoes.add(v);
                        break;
                    }
                    case "require_approval_over": {
                        Map<String, Object> v = Js.obj();
                        put(v, "id", inv, "id");
                        v.put("kind", "approval");
                        put(v, "when", inv, "when");
                        Map<String, Object> over = Js.obj();
                        put(over, "path", inv, "amount");
                        put(over, "threshold", inv, "threshold");
                        v.put("over", over);
                        put(v, "unless", inv, "approved");
                        vetoes.add(v);
                        break;
                    }
                    case "cap":
                    case "rate": {
                        Map<String, Object> u = Js.obj();
                        put(u, "id", inv, "id");
                        u.put("kind", k);
                        u.put("reason", "windowed total: bounded by maxExposure, not by a per-action veto");
                        unmodeled.add(u);
                        break;
                    }
                    default: {
                        Map<String, Object> u = Js.obj();
                        put(u, "id", inv, "id");
                        put(u, "kind", inv, "kind");
                        u.put("reason", "needs action history");
                        unmodeled.add(u);
                    }
                }
            }
        }
        return Js.obj("vetoes", vetoes, "unmodeled", unmodeled);
    }
}
