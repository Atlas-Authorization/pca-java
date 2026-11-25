package net.atlasauth.pca;

import java.util.Map;
import net.atlasauth.pca.actions.importers.GraphqlImporter;
import net.atlasauth.pca.actions.importers.GrpcImporter;
import org.junit.jupiter.api.Test;

class ActionsImportSdlDiffTest {
    private static final String M = "ref-actions-import-sdl";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** A {"$bytes": b64url} argument is the byte string itself. */
    private static Object bytesOf(Object x) {
        if (!(x instanceof Map) || !(m(x).get("$bytes") instanceof String)) return x;
        String s = (String) m(x).get("$bytes");
        return s.isEmpty() ? new byte[0] : Keys.unb64u(s);
    }

    @Test void parseGraphqlSdl() throws Exception { OracleCases.each(M, "parseGraphqlSdl", a -> GraphqlImporter.parseGraphqlSdl((String) a.get(0)).toJson()); }
    @Test void fromIntrospection() throws Exception { OracleCases.each(M, "fromIntrospection", a -> GraphqlImporter.fromIntrospection(a.get(0)).toJson()); }
    @Test void importGraphql() throws Exception { OracleCases.each(M, "importGraphql", a -> GraphqlImporter.importGraphql(a.get(0), m(a.get(1)))); }
    @Test void parseProto() throws Exception { OracleCases.each(M, "parseProto", a -> GrpcImporter.parseProto((String) a.get(0)).toJson()); }
    @Test void parseDescriptorSet() throws Exception { OracleCases.each(M, "parseDescriptorSet", a -> GrpcImporter.parseDescriptorSet((byte[]) bytesOf(a.get(0))).toJson()); }
    @Test void importGrpc() throws Exception { OracleCases.each(M, "importGrpc", a -> GrpcImporter.importGrpc(bytesOf(a.get(0)), m(a.get(1)))); }
}
