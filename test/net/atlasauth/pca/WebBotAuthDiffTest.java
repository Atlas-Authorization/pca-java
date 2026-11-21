package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.webbotauth.ContentDigest;
import net.atlasauth.pca.webbotauth.DirectoryFetch;
import net.atlasauth.pca.webbotauth.SignedDirectory;
import net.atlasauth.pca.webbotauth.WebBotAuth;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of Web Bot Auth (RFC 9421 message signatures, signed directory, Content-Digest, proof binding). */
public class WebBotAuthDiffTest {
    private static final String M = "ref-webbotauth";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static boolean isBytes(Object o) { return o instanceof Map && ((Map<?, ?>) o).containsKey("$bytes"); }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("tag", WebBotAuth.WEB_BOT_AUTH_TAG);
            o.put("alg", WebBotAuth.WEB_BOT_AUTH_ALG);
            o.put("path", WebBotAuth.WELL_KNOWN_DIRECTORY_PATH);
            o.put("ct", WebBotAuth.DIRECTORY_CONTENT_TYPE);
            o.put("label", WebBotAuth.DEFAULT_SIGNATURE_LABEL);
            o.put("exp", new Json.Num(Integer.toString(WebBotAuth.DEFAULT_EXPIRES_SEC)));
            o.put("agent", WebBotAuth.SIGNATURE_AGENT_HEADER);
            o.put("pca", WebBotAuth.PCA_HEADER);
            o.put("comp", WebBotAuth.PCA_PROOF_COMPONENT);
            o.put("cd", ContentDigest.CONTENT_DIGEST_HEADER);
            o.put("algs", new ArrayList<Object>(ContentDigest.CONTENT_DIGEST_ALGS));
            o.put("dtag", SignedDirectory.DIRECTORY_SIGNATURE_TAG);
            return o;
        });
    }

    @Test void jwkThumbprint() throws Exception { OracleCases.each(M, "jwkThumbprint", a -> WebBotAuth.jwkThumbprint(bytes(a.get(0)))); }

    @Test void signRequest() throws Exception { OracleCases.each(M, "signRequest", a -> WebBotAuth.signRequest(m(a.get(0)))); }

    // ---- verify

    /** The oracle's key-resolver spec: keyid to {"$bytes"} | JWK | null | {"$throw": true}; an unlisted keyid resolves to null. */
    private static WebBotAuth.KeyResolver resolver(Map<String, Object> spec) {
        return kid -> {
            Object v = spec.get(kid);
            if (v instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) v).get("$throw"))) throw new IllegalStateException("resolver down");
            if (isBytes(v)) return bytes(v);
            return v;
        };
    }

    private static WebBotAuth.ReplayCache cache(Object spec) {
        if ("always".equals(spec)) return (k, e, n) -> true;
        if ("never".equals(spec)) return (k, e, n) -> false;
        if ("throw".equals(spec)) return (k, e, n) -> { throw new IllegalStateException("cache down"); };
        if ("memory".equals(spec)) return WebBotAuth.memoryReplayCache();
        if (spec instanceof String && ((String) spec).startsWith("memory:")) return WebBotAuth.memoryReplayCache(Integer.parseInt(((String) spec).substring(7)));
        throw new IllegalArgumentException("unknown cache spec " + spec);
    }

    private static Map<String, Object> vopts(Map<String, Object> op) {
        Map<String, Object> out = new LinkedHashMap<>(op);
        if (out.get("resolveKey") instanceof Map) out.put("resolveKey", resolver(m(out.get("resolveKey"))));
        if ("Infinity".equals(out.get("maxLifetimeSec"))) out.put("maxLifetimeSec", Double.POSITIVE_INFINITY);
        if (out.containsKey("replayCache")) out.put("replayCache", cache(out.get("replayCache")));
        return out;
    }

    private static Map<String, Object> norm(Map<String, Object> r) {
        Map<String, Object> out = new LinkedHashMap<>(r);
        if (out.get("reason") instanceof String) out.put("reason", ((String) out.get("reason")).replaceAll("(?s)^(invalid PCActn in PCA-Action): .*$", "$1"));
        return out;
    }

    @Test void verifySignedRequest() throws Exception {
        OracleCases.each(M, "verifySignedRequest", a -> {
            int times = a.size() > 2 ? (int) (double) OracleCases.num(a.get(2)) : 1;
            Map<String, Object> vo = vopts(m(a.get(1)));
            List<Object> rs = new ArrayList<>();
            for (int i = 0; i < times; i++) rs.add(norm(WebBotAuth.verifySignedRequest(m(a.get(0)), vo)));
            return times == 1 ? rs.get(0) : rs;
        });
    }

    @Test void verifySignedRequestWithProof() throws Exception {
        OracleCases.each(M, "verifySignedRequestWithProof", a -> norm(WebBotAuth.verifySignedRequestWithProof(m(a.get(0)), vopts(m(a.get(1))))));
    }

    // ---- directory + replay cache

    private static List<Map<String, Object>> dirKeys(Object o) {
        List<Map<String, Object>> keys = new ArrayList<>();
        for (Object k : l(o)) {
            Map<String, Object> e = new LinkedHashMap<>(m(k));
            e.put("publicKey", bytes(e.get("publicKey")));
            keys.add(e);
        }
        return keys;
    }

    @Test void directory() throws Exception {
        OracleCases.each(M, "buildKeyDirectory", a -> WebBotAuth.buildKeyDirectory(dirKeys(a.get(0))));
        OracleCases.each(M, "resolveFromDirectory", a -> WebBotAuth.resolveFromDirectory(m(a.get(0)), (String) a.get(1)));
        OracleCases.each(M, "directoryHandler", a -> {
            Function<String, Map<String, Object>> h = WebBotAuth.directoryHandler(dirKeys(a.get(0)));
            List<Object> out = new ArrayList<>();
            for (Object p : l(a.get(1))) out.add(h.apply((String) p));
            return out;
        });
    }

    @Test void memoryReplayCache() throws Exception {
        OracleCases.each(M, "memoryReplayCache", a -> {
            WebBotAuth.ReplayCache c = a.get(0) == null ? WebBotAuth.memoryReplayCache() : WebBotAuth.memoryReplayCache((int) (double) OracleCases.num(a.get(0)));
            List<Object> out = new ArrayList<>();
            for (Object op : l(a.get(1))) {
                List<Object> o = l(op);
                try {
                    out.add(c.claim((String) o.get(0), OracleCases.num(o.get(1)), OracleCases.num(o.get(2))));
                } catch (Exception e) {
                    out.add("throw");
                }
            }
            return out;
        });
    }

    // ---- proof binding

    @Test void proof() throws Exception {
        OracleCases.each(M, "proofHeaders", a -> WebBotAuth.proofHeaders(a.get(0)));
        OracleCases.each(M, "decodeProofHeader", a -> WebBotAuth.decodeProofHeader((String) a.get(0)));
        OracleCases.each(M, "signRequestWithProof", a -> WebBotAuth.signRequestWithProof(m(a.get(0))));
    }

    // ---- Content-Digest

    private static Object body(Object o) { return isBytes(o) ? (Object) bytes(o) : o; }

    @SuppressWarnings("unchecked")
    @Test void contentDigest() throws Exception {
        OracleCases.each(M, "contentDigestBytes", a -> ContentDigest.contentDigestBytes(body(a.get(0)), (String) a.get(1)));
        OracleCases.each(M, "contentDigestHeader", a -> a.size() > 1 ? ContentDigest.contentDigestHeader(body(a.get(0)), (List<String>) a.get(1)) : ContentDigest.contentDigestHeader(body(a.get(0))));
        OracleCases.each(M, "parseContentDigest", a -> ContentDigest.parseContentDigest((String) a.get(0)));
        OracleCases.each(M, "verifyContentDigest", a -> {
            List<String> req = a.size() > 2 && a.get(2) != null && m(a.get(2)).get("require") != null ? (List<String>) m(a.get(2)).get("require") : null;
            return ContentDigest.verifyContentDigest((String) a.get(0), body(a.get(1)), req);
        });
    }

    // ---- signed directory

    private static Map<String, Object> signInput(Map<String, Object> in) { return in; }

    @Test void signedDirectory() throws Exception {
        OracleCases.each(M, "parseKeyDirectory", a -> SignedDirectory.parseKeyDirectory((String) a.get(0)));
        OracleCases.each(M, "signDirectoryResponse", a -> SignedDirectory.signDirectoryResponse(signInput(m(a.get(0)))));
        OracleCases.each(M, "verifyDirectoryResponse", a -> SignedDirectory.verifyDirectoryResponse(m(a.get(0))));
    }

    /** The oracle's scripted fetch: records the URL and headers, answers {status, headers, body} (or throws for "throw"). */
    @Test void fetchKeyDirectory() throws Exception {
        OracleCases.each(M, "fetchKeyDirectory", a -> {
            Map<String, Object> spec = m(a.get(1));
            Object res = spec.get("response");
            Object[] called = new Object[1];
            DirectoryFetch.Fetcher fetcher = (url, headers, timeout) -> {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("url", url);
                c.put("headers", new LinkedHashMap<String, Object>(headers));
                c.put("redirect", "error");
                called[0] = c;
                if ("throw".equals(res)) throw new IllegalStateException("network down");
                Map<String, Object> r = m(res);
                Map<String, Object> hs = r.get("headers") == null ? new LinkedHashMap<>() : m(r.get("headers"));
                return new DirectoryFetch.Response() {
                    @Override public int status() { return (int) (double) OracleCases.num(r.get("status")); }
                    @Override public String header(String name) { Object v = hs.get(name.toLowerCase()); return v == null ? null : (String) v; }
                    @Override public String text() { return (String) r.get("body"); }
                };
            };
            Map<String, Object> options = new LinkedHashMap<>();
            if (spec.get("options") != null) options.putAll(m(spec.get("options")));
            options.put("fetch", fetcher);
            Map<String, Object> out = new LinkedHashMap<>();
            try {
                out.put("directory", DirectoryFetch.fetchKeyDirectory((String) a.get(0), options));
            } catch (Exception e) {
                out.put("error", Boolean.TRUE);
                String msg = e.getMessage() == null ? "" : e.getMessage();
                out.put("message", msg.startsWith("directory ") || msg.equals("Invalid URL") ? msg.replaceAll("(?s)^(directory signature): .*$", "$1") : "other");
            }
            out.put("called", called[0]);
            return out;
        });
    }
}
