package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Policy classes (packages/pca/src/policy-classes.ts): a decision is the meet of every class consulted; denied_by / escalated_by name
 * who said no. Fail-strict and total. Replays packages/pca/conformance/policy-classes-vectors.json. The result is a plain map.
 */
public final class PolicyClasses {
    private PolicyClasses() {}

    public static final List<String> CLASSES = List.of("constitution", "regulatory", "org", "blueprint", "user");
    private static final List<String> KEYS = List.of("class", "revision", "digest", "decision");

    /** Null = a well-formed list: closed members, known classes, each at most once. */
    public static String listError(Object list) {
        if (!(list instanceof List)) return "policy classes must be an array";
        List<?> l = (List<?>) list;
        if (l.size() > CLASSES.size()) return "more than " + CLASSES.size() + " policy classes";
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < l.size(); i++) {
            if (!(l.get(i) instanceof Map)) return "policy_classes[" + i + "] must be an object";
            Map<?, ?> v = (Map<?, ?>) l.get(i);
            for (Object k : v.keySet()) if (!KEYS.contains(k)) return "policy_classes[" + i + "] has unknown member '" + k + "'";
            Object c = v.get("class");
            if (!(c instanceof String) || !CLASSES.contains(c)) return "policy_classes[" + i + "].class is not a known class";
            if (!seen.add((String) c)) return "policy class '" + c + "' appears twice";
            if (!Json.isSafeInt(v.get("revision")) || Json.asLong(v.get("revision")) < 0) return "policy_classes[" + i + "].revision must be a non-negative safe integer";
            Object d = v.get("digest");
            if (!(d instanceof String) || ((String) d).isEmpty() || ((String) d).length() > 128) return "policy_classes[" + i + "].digest invalid";
            Object dec = v.get("decision");
            if (!"allow".equals(dec) && !"escalate".equals(dec) && !"deny".equals(dec)) return "policy_classes[" + i + "].decision must be allow, escalate or deny";
        }
        return null;
    }

    private static Map<String, Object> none(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("decision", "deny");
        m.put("classes", new ArrayList<Object>());
        m.put("denied_by", new ArrayList<Object>());
        m.put("escalated_by", new ArrayList<Object>());
        m.put("reason", reason);
        return m;
    }

    /** {decision, classes, denied_by, escalated_by[, reason]}. */
    public static Map<String, Object> decide(Object list) {
        try {
            if (list instanceof List && ((List<?>) list).isEmpty()) return none("no_policy_class");
            String e = listError(list);
            if (e != null) return none("malformed policy classes: " + e);
            List<Map<String, Object>> classes = new ArrayList<>();
            for (Object o : (List<?>) list) {
                Map<String, Object> c = new LinkedHashMap<>();
                for (String k : KEYS) c.put(k, ((Map<?, ?>) o).get(k));
                classes.add(c);
            }
            classes.sort((a, b) -> Integer.compare(CLASSES.indexOf(a.get("class")), CLASSES.indexOf(b.get("class"))));
            String d = "allow";
            List<Object> denied = new ArrayList<>(), escalated = new ArrayList<>();
            for (Map<String, Object> c : classes) {
                d = Decision.meet(d, (String) c.get("decision"));
                if ("deny".equals(c.get("decision"))) denied.add(c.get("class"));
                if ("escalate".equals(c.get("decision"))) escalated.add(c.get("class"));
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("decision", d);
            m.put("classes", new ArrayList<Object>(classes));
            m.put("denied_by", denied);
            m.put("escalated_by", escalated);
            return m;
        } catch (RuntimeException ex) {
            return none("evaluation error (fail closed)");
        }
    }
}
