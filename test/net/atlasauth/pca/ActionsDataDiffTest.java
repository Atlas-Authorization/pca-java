package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import net.atlasauth.pca.actions.ActionBuiltin;
import net.atlasauth.pca.actions.ActionTemplates;
import org.junit.jupiter.api.Test;

class ActionsDataDiffTest {
    private static final String M = "ref-actions-data";

    @Test void builtinDefs() throws Exception { OracleCases.each(M, "builtinDefs", a -> ActionBuiltin.builtinDefs()); }
    @Test void domainDefs() throws Exception { OracleCases.each(M, "domainDefs", a -> ActionBuiltin.domainDefs()); }
    @Test void corePackDefs() throws Exception { OracleCases.each(M, "corePackDefs", a -> ActionBuiltin.corePackDefs()); }
    @Test void legacy() throws Exception {
        OracleCases.each(M, "legacyCatalog", a -> ActionBuiltin.legacyCatalog());
        OracleCases.each(M, "legacyOntologyEffect", a -> ActionBuiltin.legacyOntologyEffect());
        OracleCases.each(M, "resolutions", a -> ActionBuiltin.resolutions());
        OracleCases.each(M, "domainBindings", a -> ActionBuiltin.domainVerbBindings());
    }
    @Test void coreDigests() throws Exception {
        OracleCases.each(M, "coreDigests", a -> {
            List<Object> out = new ArrayList<>();
            for (Object d : ActionBuiltin.corePackDefs()) {
                @SuppressWarnings("unchecked") java.util.Map<String, Object> m = (java.util.Map<String, Object>) d;
                out.add(List.of(m.get("verb"), Actions.defDigest(m)));
            }
            return out;
        });
    }
    @Test void domain() throws Exception {
        OracleCases.each(M, "domainVerbs", a -> ActionBuiltin.domainVerbs((String) a.get(0), null));
        OracleCases.each(M, "domainRoles", a -> ActionBuiltin.domainRoles((String) a.get(0)));
    }
    @Test void release() throws Exception {
        OracleCases.each(M, "releasedBuiltinDefs", a -> Json.stringify(ActionBuiltin.releasedBuiltinDefs(null)).equals(Json.stringify(ActionBuiltin.builtinDefs())));
        OracleCases.each(M, "builtinConfirmed", a -> ActionBuiltin.builtinReviewOpts(null) != null);
    }
    @Test void templates() throws Exception {
        OracleCases.each(M, "starterTemplates", a -> ActionTemplates.starterTemplates());
        OracleCases.each(M, "starterTemplate", a -> ActionTemplates.starterTemplate((String) a.get(0)));
        OracleCases.each(M, "templateYaml", a -> ActionTemplates.yaml((String) a.get(0), a.get(1)));
        OracleCases.each(M, "templateTraits", a -> ActionTemplates.traits((String) a.get(0), a.get(1)));
    }
}
