package net.atlasauth.pca;

import java.util.Map;
import net.atlasauth.pca.schema.Schema;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the wire JSON Schemas and the structural validator. */
class SchemaDiffTest {
    private static final String MODULE = "ref-schema";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> pick(Object s) {
        if (s instanceof Map) return (Map<String, Object>) s;
        switch ((String) s) {
            case "PCActn": return Schema.pcactnSchema();
            case "Capability": return Schema.capabilitySchema();
            case "PcaDiscoveryDocument": return Schema.discoverySchema();
            default: throw new IllegalArgumentException("unknown schema " + s);
        }
    }

    @Test void schemas() throws Exception { OracleCases.each(MODULE, "schemas", a -> Schema.allSchemas()); }

    @Test void validate() throws Exception { OracleCases.each(MODULE, "validate", a -> Schema.validate(pick(a.get(0)), a.get(1)).toJson()); }
}
