package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentSchema;
import org.junit.jupiter.api.Test;

class IntentSchemaDiffTest {
    private static final String M = "ref-intent-schema";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @Test void deriveSchemaOmega() throws Exception {
        OracleCases.each(M, "deriveSchemaOmega", a -> {
            IntentSchema.SchemaOmega r = IntentSchema.deriveOmegaFromSchema(mp(a.get(0)));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("omega", IntentOmega.omegaToJson(r.omega));
            out.put("overrides", r.overrides);
            out.put("defaults", r.defaults);
            out.put("canonOf", new LinkedHashMap<String, Object>(r.canonOf));
            return out;
        });
    }

    @Test void canonValue() throws Exception { OracleCases.each(M, "canonValue", a -> IntentSchema.canonValue(mp(a.get(0)), a.get(1))); }

    @Test void effectiveSensitivity() throws Exception {
        OracleCases.each(M, "effectiveSensitivity", a -> IntentSchema.effectiveSensitivity(mp(a.get(0)), a.size() > 1 ? mp(a.get(1)) : null));
    }

    @Test void verbReversibility() throws Exception { OracleCases.each(M, "verbReversibility", a -> IntentSchema.verbReversibility(mp(a.get(0)))); }

    @Test void walletFloorOverrides() throws Exception {
        OracleCases.each(M, "walletFloorOverrides", a -> IntentSchema.walletFloorOverrides(IntentOmega.arr(a.get(0)), a.size() > 1 ? mp(a.get(1)) : null));
    }
}
