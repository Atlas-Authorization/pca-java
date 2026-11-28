package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.research.Immune;
import org.junit.jupiter.api.Test;

/** The immune system's adaptation, signed tightening proposals and durable store against the reference. */
public class ImmuneDiffTest {
    static final String MODULE = "ref-immune-java";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static byte[] sd(Object label) { return CoreStoresDiffTest.seed("immune/" + label); }

    /** The pinned guardian "@g" is the public key of the seed labelled g. */
    static Map<String, Object> pin(Object opts) {
        Map<String, Object> o = m(opts);
        if (o == null) return null;
        if (!"@g".equals(o.get("guardian"))) return o;
        Map<String, Object> c = new LinkedHashMap<>(o);
        c.put("guardian", Keys.edFromSeed(sd("g")).id());
        return c;
    }

    static Map<String, Object> err() { Map<String, Object> e = new LinkedHashMap<>(); e.put("$err", "Error"); return e; }

    @Test void adapt() throws Exception { OracleCases.each(MODULE, "adapt", a -> Immune.adapt(a.get(0), m(a.get(1)))); }

    @Test void noWiden() throws Exception { OracleCases.each(MODULE, "noWidenViolation", a -> Immune.noWidenViolation(m(a.get(0)), m(a.get(1)))); }

    @Test void digests() throws Exception {
        OracleCases.each(MODULE, "policyDigest", a -> Immune.policyDigest(m(a.get(0))));
        OracleCases.each(MODULE, "immuneStateDigest", a -> Immune.immuneStateDigest(m(a.get(0))));
    }

    @Test void issue() throws Exception {
        OracleCases.each(MODULE, "issueTighteningProposal", a -> Immune.issueTighteningProposal(m(a.get(0)), m(a.get(1)), a.get(2), a.get(3), sd(a.get(4))));
    }

    @Test void apply() throws Exception {
        OracleCases.each(MODULE, "applyTightening", a -> Immune.applyTightening(m(a.get(0)), m(a.get(1)), pin(a.get(2))));
    }

    @Test void store() throws Exception {
        OracleCases.each(MODULE, "store", a -> {
            AtomicKv kv = new MemoryAtomicKv();
            String subject = (String) a.get(0);
            Immune.ImmuneStore st = Immune.createImmuneStore(kv, subject);
            List<Object> out = new ArrayList<>();
            for (Object o : l(a.get(1))) {
                List<Object> op = l(o);
                try {
                    switch ((String) op.get(0)) {
                        case "seed": kv.set("immune/state/" + subject, op.get(1) == null ? AtomicKv.JSON_NULL : op.get(1)); out.add(null); break;
                        case "get": out.add(st.get()); break;
                        case "observe": out.add(st.observe(m(op.get(1)))); break;
                        case "lastEpoch": out.add(StoreJs.num(st.lastEpoch())); break;
                        case "apply": out.add(st.apply(m(op.get(1)), m(op.get(2)), pin(op.get(3)))); break;
                        default: throw new IllegalStateException("op " + op.get(0));
                    }
                } catch (RuntimeException e) { out.add(err()); }
            }
            return out;
        });
    }
}
