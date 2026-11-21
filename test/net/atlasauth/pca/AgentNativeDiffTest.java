package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import org.junit.jupiter.api.Test;

/**
 * Replays every case of the reference oracle for the agent-native module (caution, rationale, tool-schema firewall, envelope
 * introspection, leases): 1632 cases, every fn dispatched, an unhandled fn fails the test. Total functions compare their returned
 * value (reason strings included); a {"$throws"} case needs the native to throw.
 */
public class AgentNativeDiffTest {
    private static final Set<String> FNS = Set.of("signCaution", "verifyCaution", "combineCaution", "combineSignedCaution", "checkCautionMonotone",
        "isStrongSalt", "bindRationale", "verifyRationale", "auditRationale", "validateArgSchema", "toolSchemaCaveat", "evaluateToolSchema",
        "toolSchemaEvaluator", "predicatesCaveat", "actionSpendUsd", "agentNativeCaveatEvaluator", "describeEnvelope", "envelopePermits",
        "envelopePermitsToolCall", "grantLease", "leaseState", "signHeartbeat", "renewLease", "constants");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    /** {"$num": "NaN" | "Infinity" | "-Infinity"} is that double; {"$bytes": b64u} is the byte array. */
    @SuppressWarnings("unchecked")
    private static Object dec(Object v) {
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<Object>) v) out.add(dec(x)); return out; }
        if (!(v instanceof Map)) return v;
        Map<String, Object> mm = (Map<String, Object>) v;
        if (mm.size() == 1 && mm.get("$num") instanceof String) {
            String s = (String) mm.get("$num");
            return s.equals("NaN") ? Double.NaN : s.equals("Infinity") ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY;
        }
        if (mm.size() == 1 && mm.get("$bytes") instanceof String) return Keys.unb64u((String) mm.get("$bytes"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), dec(e.getValue()));
        return out;
    }

    private static BiFunction<String, Object, Object> judge(String spec) {
        if (spec.equals("true")) return (r, a) -> Boolean.TRUE;
        if (spec.equals("false")) return (r, a) -> Boolean.FALSE;
        if (spec.equals("throw")) return (r, a) -> { throw new IllegalStateException("judge"); };
        if (spec.equals("truthy")) return (r, a) -> "yes";
        if (spec.startsWith("contains:")) return (r, a) -> r.contains(spec.substring("contains:".length()));
        if (spec.startsWith("action-verb:")) return (r, a) -> a instanceof Map && spec.substring("action-verb:".length()).equals(((Map<?, ?>) a).get("verb"));
        throw new AssertionError("unknown judge spec " + spec);
    }

    private static Map<String, Object> firewall(Authorize.ToolSchemaResult r) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("ok", r.ok);
        if (r.reason != null) o.put("reason", r.reason);
        return o;
    }

    private static Object call(String fn, List<?> a) {
        switch (fn) {
            case "signCaution": return SignersMore.signCaution(m(arg(a, 0)), Keys.edFromSeed((byte[]) arg(a, 1)));
            case "signHeartbeat": return SignersMore.signHeartbeat(m(arg(a, 0)), Keys.edFromSeed((byte[]) arg(a, 1)));
            case "verifyCaution": return AgentNative.verifyCaution(arg(a, 0), arg(a, 1), arg(a, 2));
            case "combineCaution": return AgentNative.combineCaution(arg(a, 0), arg(a, 1));
            case "combineSignedCaution": return AgentNative.combineSignedCaution(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3));
            case "checkCautionMonotone": return AgentNative.checkCautionMonotone(arg(a, 0));
            case "isStrongSalt": return AgentNative.isStrongSalt(arg(a, 0));
            case "bindRationale": return AgentNative.bindRationale(arg(a, 0), arg(a, 1), arg(a, 2));
            case "verifyRationale":
                return a.size() < 3 ? AgentNative.verifyRationale(arg(a, 0), arg(a, 1)) : AgentNative.verifyRationale(arg(a, 0), arg(a, 1), arg(a, 2));
            case "auditRationale": return AgentNative.auditRationale(arg(a, 0), arg(a, 1), arg(a, 2), judge((String) arg(a, 3)));
            case "validateArgSchema": return Authorize.validateArgSchema(arg(a, 0));
            case "toolSchemaCaveat": return AgentNative.toolSchemaCaveat(arg(a, 0), arg(a, 1));
            case "evaluateToolSchema": return firewall(Authorize.evaluateToolSchema(arg(a, 0), arg(a, 1)));
            case "toolSchemaEvaluator": return AgentNative.toolSchemaEvaluator(arg(a, 0), arg(a, 1));
            case "predicatesCaveat": return AgentNative.predicatesCaveat(arg(a, 0));
            case "actionSpendUsd": { Double d = AgentNative.actionSpendUsd(arg(a, 0)); return d != null && d == 0.0 ? Double.valueOf(0.0) : d; }
            case "agentNativeCaveatEvaluator": return AgentNative.agentNativeCaveatEvaluator(arg(a, 0), arg(a, 1));
            case "describeEnvelope":
                return AgentNative.describeEnvelope(arg(a, 0), arg(a, 1), (String) arg(a, 2), arg(a, 3) == null ? null : m(arg(a, 3)));
            case "envelopePermits": return AgentNative.envelopePermits(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3), arg(a, 4));
            case "envelopePermitsToolCall": return AgentNative.envelopePermitsToolCall(arg(a, 0), arg(a, 1));
            case "grantLease": return AgentNative.grantLease(arg(a, 0));
            case "leaseState": return AgentNative.leaseState(arg(a, 0), arg(a, 1));
            case "renewLease": return AgentNative.renewCapabilityLease(arg(a, 0), arg(a, 1), arg(a, 2));
            case "constants": return AgentNative.constants();
            default: throw new AssertionError("unhandled fn " + fn);
        }
    }

    @Test void replayAllCases() throws Exception {
        List<Map<String, Object>> cases = BaseOracle.all("ref-agent-native");
        assertEquals(1632, cases.size());
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : cases) {
            String fn = (String) c.get("fn");
            assertTrue(FNS.contains(fn), "unhandled fn " + fn);
            String d = OracleCases.diff(c, c.get("out"), args -> call(fn, (List<?>) dec(args)));
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
