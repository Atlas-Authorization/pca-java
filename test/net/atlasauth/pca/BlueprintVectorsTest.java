package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The agent-blueprint corpus (blueprint-vectors.json). A missing file FAILS. */
public class BlueprintVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("blueprint-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    @Test void scenarios() {
        List<Object> recs = (List<Object>) DOC.get("records");
        assertEquals(9, recs.size());
        for (int i = 0; i < recs.size(); i++) assertEquals(i != 8, Blueprint.verify(recs.get(i)), "record " + i);
        List<String> ops = new ArrayList<>();
        ops.add((String) DOC.get("operator"));
        for (Object x : (List<Object>) DOC.get("scenarios")) {
            Map<String, Object> s = m(x);
            String name = (String) s.get("name");
            Blueprint.Registry reg = new Blueprint.Registry(ops);
            for (Object y : (List<Object>) s.get("steps")) {
                Map<String, Object> st = m(y);
                Map<String, Object> exp = m(st.get("expect"));
                if ("accept".equals(st.get("op"))) {
                    Blueprint.Accept g = reg.accept(recs.get((int) Json.asLong(st.get("record"))));
                    assertEquals(exp.get("ok"), g.code == null, name + ": ok");
                    if (g.code == null) assertEquals(exp.get("replaced"), g.replaced, name + ": replaced");
                    else assertEquals(exp.get("code"), g.code, name + ": code");
                    continue;
                }
                Map<String, Object> o = m(st.get("opts"));
                Long min = o.containsKey("minEpoch") ? Long.valueOf(Json.asLong(o.get("minEpoch"))) : null;
                Blueprint.Decision d = Blueprint.check(st.get("chain"), reg, o.get("now"), (String) o.get("mode"), min);
                assertEquals(exp.get("decision"), d.decision, name + ": decision");
                if (exp.containsKey("code")) assertEquals(exp.get("code"), d.code, name + ": code");
                if (exp.containsKey("blueprint")) assertEquals(exp.get("blueprint"), d.blueprint, name + ": blueprint");
                if (exp.containsKey("governed")) assertEquals(exp.get("governed"), d.governed, name + ": governed");
                if ("escalate".equals(exp.get("decision"))) {
                    assertEquals(Json.asLong(exp.get("have")), d.have, name + ": have");
                    assertEquals(Json.asLong(exp.get("need")), d.need, name + ": need");
                }
            }
        }
    }
}
