package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.compliance.Compliance;
import org.junit.jupiter.api.Test;

class ComplianceDiffTest {
    private static final String M = "ref-compliance";

    private static Object at(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @Test void toAuditEvent() throws Exception { OracleCases.each(M, "toAuditEvent", a -> Compliance.toAuditEvent(at(a, 0))); }

    @Test void controlMappings() throws Exception {
        OracleCases.each(M, "controlMappings", a -> a.isEmpty() ? Compliance.controlMappings() : Compliance.controlMappings(a.get(0)));
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("COMPLIANCE_FRAMEWORKS", Compliance.COMPLIANCE_FRAMEWORKS);
            m.put("CONTROL_MAPPINGS", Compliance.CONTROL_MAPPINGS);
            return m;
        });
    }

    @Test void toComplianceReport() throws Exception { OracleCases.each(M, "toComplianceReport", a -> Compliance.toComplianceReport(at(a, 0), at(a, 1))); }

    @Test void renderJson() throws Exception { OracleCases.each(M, "renderJson", a -> Compliance.renderJson(at(a, 0))); }

    @Test void renderMarkdown() throws Exception { OracleCases.each(M, "renderMarkdown", a -> Compliance.renderMarkdown(at(a, 0))); }

    @Test void frameworkReport() throws Exception { OracleCases.each(M, "frameworkReport", a -> Compliance.frameworkReport(at(a, 0), at(a, 1), at(a, 2))); }

    @Test void frameworkReportToMarkdown() throws Exception { OracleCases.each(M, "frameworkReportToMarkdown", a -> Compliance.frameworkReportToMarkdown(at(a, 0))); }
}
