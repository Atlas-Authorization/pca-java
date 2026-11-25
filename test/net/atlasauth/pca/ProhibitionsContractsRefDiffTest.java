package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The prohibitions and contracts names the shared vectors and the base prohibitions corpus do not reach, against the reference corpora
 * (ref-prohibitions 1637 cases, ref-contracts 1269): every function, every case. Where the reference tells an absent option from a null
 * one, the replay calls the entry point that keeps the difference; the public methods read null as "not given".
 */
class ProhibitionsContractsRefDiffTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    /** The loader has replaced each {"$seed": label} by the base64url seed; anything else is not a key and the reference refuses it. */
    private static byte[] seed(Object s) {
        byte[] b = Pca.decodeB64uStrict(s, 32);
        if (b == null) throw new IllegalArgumentException("not a signing key");
        return b;
    }

    private static Map<String, Object> need(Object o) {
        if (m(o) == null) throw new IllegalArgumentException("not an object");
        return m(o);
    }

    /** JavaScript object spread of a value: a string or a list contributes its indices. */
    private static Map<String, Object> spread(Object o) {
        if (o == null) throw new IllegalArgumentException("null");
        if (o instanceof Map) return m(o);
        Map<String, Object> out = new LinkedHashMap<>();
        if (o instanceof List) for (int i = 0; i < ((List<?>) o).size(); i++) out.put(Integer.toString(i), ((List<?>) o).get(i));
        if (o instanceof String) for (int i = 0; i < ((String) o).length(); i++) out.put(Integer.toString(i), String.valueOf(((String) o).charAt(i)));
        return out;
    }

    private static void replay(String module, int total, Map<String, OracleCases.Fn> table) throws Exception {
        List<Map<String, Object>> all = BaseOracle.of(module, null);
        assertEquals(total, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(table.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : table.entrySet()) OracleCases.each(module, e.getKey(), e.getValue());
    }

    @Test void prohibitions() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", a -> Prohibitions.map("CONSTITUTION_VERSION", Prohibitions.CONSTITUTION_VERSION, "CONSTITUTION_SIG_DOMAIN", Prohibitions.CONSTITUTION_SIG_DOMAIN,
            "EVIDENCE_VERSION", Prohibitions.EVIDENCE_VERSION, "SAFETY_EVIDENCE_SIG_DOMAIN", Prohibitions.SAFETY_EVIDENCE_SIG_DOMAIN, "STATE_DIGEST_DOMAIN", Prohibitions.STATE_DIGEST_DOMAIN,
            "STATE_CHAIN_DOMAIN", Prohibitions.STATE_CHAIN_DOMAIN, "MAX_LEDGER", Prohibitions.MAX_LEDGER, "MAX_INVARIANTS", Prohibitions.MAX_INVARIANTS, "MAX_DEADLINE", Prohibitions.MAX_DEADLINE));
        f.put("validateWhen", a -> Prohibitions.validateWhen(arg(a, 0), arg(a, 1) instanceof String ? (String) arg(a, 1) : IntentRevocation.jsText(arg(a, 1), a.size() > 1)));
        f.put("whenMatches", a -> Prohibitions.whenMatches(arg(a, 0), arg(a, 1)));
        f.put("signConstitution", a -> SignersMore.signConstitution(need(arg(a, 0)), Keys.edFromSeed(seed(arg(a, 1)))));
        f.put("advanceState", a -> Prohibitions.advanceStateRef(arg(a, 0), arg(a, 1), arg(a, 2), a.size() > 3 ? a.get(3) : Prohibitions.ABSENT));
        f.put("evidenceDigest", a -> Prohibitions.evidenceDigest(arg(a, 0)));
        f.put("composeAuthority", a -> Prohibitions.composeAuthority(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3)));
        replay("ref-prohibitions", 1637, f);
    }

    /** The options of a contract advance as the reference reads them: a member that is present, even null, is a check. */
    private static Object[] opts(List<?> a, int i) {
        Object o = arg(a, i);
        if (a.size() > i && o == null) throw new IllegalArgumentException("null options"); // the reference reads a member of null
        Map<String, Object> om = m(o);
        return new Object[] {om == null ? null : om.get("now"), om != null && om.containsKey("expectedSeq") ? om.get("expectedSeq") : Prohibitions.ABSENT,
            om != null && om.containsKey("expectedStateDigest") ? om.get("expectedStateDigest") : Prohibitions.ABSENT};
    }

    @Test void contracts() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", a -> Prohibitions.map("CONTRACT_VERSION", Contracts.CONTRACT_VERSION, "CONTRACT_SIG_DOMAIN", Contracts.CONTRACT_SIG_DOMAIN, "MAX_CLAUSES", Contracts.MAX_CLAUSES,
            "MAX_CLAUSE_DEPTH", Contracts.MAX_CLAUSE_DEPTH));
        f.put("validateClause", a -> {
            Set<String> seen = new HashSet<>();
            for (Object s : (List<?>) arg(a, 1)) seen.add((String) s);
            return Contracts.validateClause(arg(a, 0), seen, (int) Math.ceil(OracleCases.num(arg(a, 2))));
        });
        f.put("contractId", a -> Contracts.contractId(spread(arg(a, 0))));
        f.put("signContract", a -> Contracts.signContract(need(arg(a, 0)), seed(arg(a, 1))));
        f.put("embeddedConstitution", a -> Contracts.embeddedConstitutionOf(arg(a, 0)));
        f.put("contractFromConstitution", a -> Contracts.contractFromConstitution(arg(a, 0)));
        f.put("checkContract", a -> Contracts.checkContract(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("advanceContract", a -> {
            if (a.size() > 3 && arg(a, 3) == null) return Contracts.advanceContractNullOptions(arg(a, 0), arg(a, 1), arg(a, 2));
            Object[] o = opts(a, 3);
            return Contracts.advanceContractRef(arg(a, 0), arg(a, 1), arg(a, 2), o[0], o[1], o[2]);
        });
        f.put("checkAndAdvanceContract", a -> {
            Object[] o = opts(a, 4);
            return Contracts.checkAndAdvanceContractRef(Boolean.TRUE.equals(arg(a, 0)), arg(a, 1), arg(a, 2), arg(a, 3), o[0], o[1], o[2]);
        });
        replay("ref-contracts", 1269, f);
    }

    @Test void thePublicEntryPointsReadNullAsNotGiven() {
        Map<String, Object> state = Prohibitions.emptyState(IntentJs.ofLong(1_700_000_000_000L));
        Map<String, Object> action = Issue.obj("action", Issue.obj("verb", "read", "resource", "/r"));
        Map<String, Object> c = Contracts.fromConstitution(Issue.obj("version", IntentJs.ofLong(1), "principal", Pca.b64(new byte[32]), "invariants", new ArrayList<>()));
        assertEquals(Json.canonicalize(Contracts.advanceContractRef(state, action, c, null, Prohibitions.ABSENT, Prohibitions.ABSENT)),
            Json.canonicalize(Contracts.advanceContract(state, action, c, null, null, null)));
        assertEquals(Json.canonicalize(Prohibitions.advanceState(action, Contracts.embeddedConstitutionOf(c), state)),
            Json.canonicalize(Prohibitions.advanceState(action, Contracts.embeddedConstitutionOf(c), state, null)));
    }
}
