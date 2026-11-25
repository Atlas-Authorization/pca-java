package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.vc.Vc;
import org.junit.jupiter.api.Test;

/**
 * Differential test of {@link Vc} against the TypeScript reference (test-data/ref-vc.json.gz): base58btc and did:key, the bundled
 * JSON-LD context, the agent-passport SD-JWT VC (issuance compared in normalized form: random salts) and RFC 9421 / Web Bot Auth
 * request signatures. The reference ran under a pinned clock; the same instant is passed here as {@code now}.
 */
public class VcDiffTest {
    static final String M = "ref-vc";
    static final double NOW = 1_700_000_100_000d;

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    static byte[] bytes(Object o) { return o == null ? null : Keys.unb64u((String) m(o).get("$bytes")); }

    static String str(Object o) {
        if (!(o instanceof String)) throw new IllegalArgumentException("not a string");
        return (String) o;
    }

    static Map<String, Object> json(String b64) {
        return m(Json.parseLenient(new String(Base64.getUrlDecoder().decode(b64), StandardCharsets.UTF_8)));
    }

    static String sha(String ascii) {
        byte[] b = new byte[ascii.length()];
        for (int i = 0; i < b.length; i++) b[i] = (byte) ascii.charAt(i);
        return Keys.b64u(net.atlasauth.pca.jose.Jose.sha256(b));
    }

    @Test void base58btcEncode() throws Exception {
        OracleCases.each(M, "base58btcEncode", a -> Vc.base58btcEncode(bytes(a.get(0))));
    }

    @Test void base58btcDecode() throws Exception {
        OracleCases.each(M, "base58btcDecode", a -> Vc.base58btcDecode(str(a.get(0))));
    }

    @Test void didKeyFromEd25519() throws Exception {
        OracleCases.each(M, "didKeyFromEd25519", a -> Vc.didKeyFromEd25519(bytes(a.get(0))));
    }

    @Test void ed25519FromDidKey() throws Exception {
        OracleCases.each(M, "ed25519FromDidKey", a -> Vc.ed25519FromDidKey(str(a.get(0))));
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("VC_CONTEXT", Vc.VC_CONTEXT);
            r.put("AGENT_PASSPORT_CONTEXT", Vc.AGENT_PASSPORT_CONTEXT);
            r.put("AGENT_PASSPORT_VC_TYPE", Vc.AGENT_PASSPORT_VC_TYPE);
            r.put("AGENT_PASSPORT_CONTEXT_DIGEST", Vc.AGENT_PASSPORT_CONTEXT_DIGEST);
            r.put("AGENT_PASSPORT_CONTEXT_DOC", Vc.AGENT_PASSPORT_CONTEXT_DOC);
            return r;
        });
    }

    @Test void resolveAgentPassportContext() throws Exception {
        OracleCases.each(M, "resolveAgentPassportContext", a -> Vc.resolveAgentPassportContext(a.get(0)));
    }

    /** The reference's normalized view of an issued credential (salts are random). */
    static Map<String, Object> normVc(String sd) {
        String[] parts = sd.split("~", -1);
        List<String> ds = new ArrayList<>();
        for (int i = 1; i < parts.length - 1; i++) ds.add(parts[i]);
        String[] hp = parts[0].split("\\.");
        Map<String, Object> h = json(hp[0]), p = json(hp[1]);
        Map<String, Object> vc = m(p.get("vc"));
        Map<String, Object> cs = vc == null ? null : m(vc.get("credentialSubject"));
        List<String> sdl = new ArrayList<>();
        if (cs != null && cs.get("_sd") instanceof List) for (Object x : (List<?>) cs.get("_sd")) sdl.add((String) x);
        Collections.sort(sdl);
        if (cs != null) cs.remove("_sd");
        boolean verified;
        try {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("now", NOW);
            Vc.verifyPassportVC(sd, Keys.edFromSeed(filled(1)).pub, o);
            verified = true;
        } catch (RuntimeException e) {
            verified = false;
        }
        List<String> dig = new ArrayList<>();
        List<List<Object>> disc = new ArrayList<>();
        for (String d : ds) {
            dig.add(sha(d));
            List<?> t = (List<?>) Json.parseLenient(new String(Base64.getUrlDecoder().decode(d), StandardCharsets.UTF_8));
            List<Object> pair = new ArrayList<>();
            pair.add(t.get(1));
            pair.add(t.get(2));
            disc.add(pair);
        }
        Collections.sort(dig);
        disc.sort((x, y) -> String.valueOf(x.get(0)).compareTo(String.valueOf(y.get(0))));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("end", parts[parts.length - 1]);
        out.put("header", h);
        out.put("payload", p);
        out.put("n", ds.size());
        out.put("digestsOk", dig.equals(sdl));
        out.put("disclosures", disc);
        out.put("verified", verified);
        return out;
    }

    static byte[] filled(int v) { byte[] b = new byte[32]; java.util.Arrays.fill(b, (byte) v); return b; }

    @Test void passportToVC() throws Exception {
        OracleCases.each(M, "passportToVC", a -> {
            Object pp = a.get(0);
            if (pp == null) throw new IllegalArgumentException("Cannot read properties of null");
            Map<String, Object> passport = m(pp) != null ? m(pp) : new LinkedHashMap<>();
            Map<String, Object> o = m(a.get(1));
            Map<String, Object> args = new LinkedHashMap<>();
            args.put("issuerKey", bytes(o.get("issuer_seed")));
            if (o.containsKey("issuer_did")) args.put("issuerDid", o.get("issuer_did"));
            if (o.containsKey("subject_did")) args.put("subjectDid", o.get("subject_did"));
            if (o.containsKey("ttl_sec")) args.put("ttlSec", o.get("ttl_sec"));
            args.put("now", NOW);
            return normVc(Vc.passportToVC(passport, args));
        });
    }

    @Test void verifyPassportVC() throws Exception {
        OracleCases.each(M, "verifyPassportVC", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("now", NOW);
            Map<String, Object> opts = a.size() > 2 ? m(a.get(2)) : null;
            if (opts != null && opts.containsKey("expectedIssuerDid")) o.put("expectedIssuerDid", opts.get("expectedIssuerDid"));
            return Vc.verifyPassportVC(a.get(0), bytes(a.get(1)), o);
        });
    }

    @Test void signRequestMessage() throws Exception {
        OracleCases.each(M, "signRequestMessage", a -> {
            Map<String, Object> in = m(a.get(0));
            Map<String, Object> args = new LinkedHashMap<>();
            args.put("method", in.get("method"));
            args.put("url", in.get("url"));
            args.put("headers", in.get("headers"));
            args.put("key", bytes(in.get("key")));
            args.put("keyid", in.get("keyid"));
            if (in.containsKey("created")) args.put("created", in.get("created"));
            if (in.containsKey("signature_agent")) args.put("signatureAgent", in.get("signature_agent"));
            args.put("now", NOW);
            return Vc.signRequestMessage(args);
        });
    }

    @Test void verifyRequestSignature() throws Exception {
        String[][] names = {{"method", "method"}, {"url", "url"}, {"headers", "headers"}, {"signature_input", "signatureInput"}, {"signature", "signature"},
            {"signature_agent", "signatureAgent"}, {"required_components", "requiredComponents"}, {"max_age_sec", "maxAgeSec"}, {"now_sec", "nowSec"}};
        OracleCases.each(M, "verifyRequestSignature", a -> {
            Map<String, Object> in = m(a.get(0));
            Map<String, Object> args = new LinkedHashMap<>();
            for (String[] n : names) if (in.containsKey(n[0])) args.put(n[1], in.get(n[0]));
            args.put("now", NOW);
            return Vc.verifyRequestSignature(args, bytes(a.get(1)));
        });
    }
}
