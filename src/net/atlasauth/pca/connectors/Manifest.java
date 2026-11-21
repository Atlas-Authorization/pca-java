package net.atlasauth.pca.connectors;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.connect.JsText;
import net.atlasauth.pca.connect.UrlBits;
import net.atlasauth.pca.connectors.ConnectorError.ManifestValidationError;
import net.atlasauth.pca.oauth.WhatwgUrl;

/** Manifest validation: an untrusted value becomes a {@link ProviderManifest} only through {@link #validateManifest} / {@link #assertManifest}. */
public final class Manifest {
    private Manifest() {}

    /** OAuth request parameters a manifest or a caller must not set through authParams / extraParams: the request builders own them. */
    public static final Set<String> RESERVED_AUTHORIZE_PARAMS = Set.of("response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method");
    public static final Set<String> RESERVED_TOKEN_PARAMS = Set.of("grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token");

    private static final Pattern ID_PATTERN = Pattern.compile("[a-z0-9][a-z0-9._-]*");
    private static final String ID_SOURCE = "^[a-z0-9][a-z0-9._-]*$";
    private static final Pattern HEADER_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9-]*");
    private static final Pattern QUERY_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_.-]*");
    private static final Set<String> FORBIDDEN_HEADERS = Set.of("host", "content-length", "content-type", "transfer-encoding", "connection", "cookie", "set-cookie");
    private static final Pattern VAR = Pattern.compile("\\{(\\w+)\\}");
    private static final Pattern WHOLE_HOST_VAR = Pattern.compile("\\{\\w+\\}(:\\d+)?");
    private static final String PLACEMENTS = "bearer | header | query";
    private static final String REFRESH_MODES = "refresh_token | none";
    private static final String CLIENT_AUTHS = "post | basic";

    /** The result of validating an untrusted manifest. */
    public static final class ManifestValidation {
        public final boolean ok;
        public final ProviderManifest manifest;
        public final List<String> issues;
        ManifestValidation(boolean ok, ProviderManifest manifest, List<String> issues) { this.ok = ok; this.manifest = manifest; this.issues = issues; }
    }

    private static boolean isNonEmptyString(Object v) { return v instanceof String && !((String) v).isEmpty(); }

    private static boolean isStringArray(Object v) {
        if (!(v instanceof List)) return false;
        for (Object x : (List<?>) v) if (!(x instanceof String)) return false;
        return true;
    }

    private static boolean isStringRecord(Object v) {
        if (!(v instanceof Map)) return false;
        for (Object x : ((Map<?, ?>) v).values()) if (!(x instanceof String)) return false;
        return true;
    }

    private static boolean has(Map<?, ?> m, String k) { return m.containsKey(k); }

    private static boolean isHttpsUrl(Object v) {
        if (!(v instanceof String) || !((String) v).startsWith("https://")) return false;
        String s = (String) v;
        // The host may carry {var} placeholders. Check the shape with them replaced by a label, and refuse credentials in the URL, a placeholder
        // that is the whole host (the caller would then choose where tokens go), and a fragment.
        String probe = VAR.matcher(s).replaceAll("x");
        WhatwgUrl u = WhatwgUrl.parse(probe);
        if (u == null) return false;
        if (!u.protocol.equals("https:") || UrlBits.hasCredentials(probe) || UrlBits.hasFragment(probe)) return false;
        String rest = s.substring("https://".length());
        int e = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '/' || c == '?' || c == '#') { e = i; break; }
        }
        return !WHOLE_HOST_VAR.matcher(rest.substring(0, e)).matches();
    }

    private static List<String> urlVars(String url) {
        List<String> out = new ArrayList<>();
        Matcher m = VAR.matcher(url);
        while (m.find()) out.add(m.group(1));
        return out;
    }

    private static List<String> strings(Object v) {
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) v) out.add((String) x);
        return out;
    }

    private static Map<String, String> stringMap(Object v) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.put((String) e.getKey(), (String) e.getValue());
        return out;
    }

    /**
     * Structurally validate an untrusted value (a parsed JSON tree) as a {@link ProviderManifest}. Pure; collects every issue rather than failing
     * on the first. Enforces the catalog invariants: a well-formed id, HTTPS endpoints, string scope lists, defaultScopes inside scopesAvailable, a
     * known tokenPlacement / refresh.mode / clientAuth, a headerName / queryParam for the matching placement, and every {var} in the URLs declared
     * in requiredVars (and the reverse).
     */
    public static ManifestValidation validateManifest(Object input) {
        List<String> issues = new ArrayList<>();
        if (!(input instanceof Map)) {
            issues.add("manifest must be an object");
            return new ManifestValidation(false, null, issues);
        }
        Map<?, ?> in = (Map<?, ?>) input;

        Object id = in.get("id");
        if (!isNonEmptyString(id)) issues.add("id must be a non-empty string");
        else if (!ID_PATTERN.matcher((String) id).matches()) issues.add("id '" + id + "' must be lowercase and match " + ID_SOURCE);

        if (!isNonEmptyString(in.get("displayName"))) issues.add("displayName must be a non-empty string");

        Object authorizeUrl = in.get("authorizeUrl");
        if (!isHttpsUrl(authorizeUrl)) issues.add("authorizeUrl must be an https:// URL");
        Object tokenUrl = in.get("tokenUrl");
        if (!isHttpsUrl(tokenUrl)) issues.add("tokenUrl must be an https:// URL");

        Object scopesAvailable = in.get("scopesAvailable");
        if (!isStringArray(scopesAvailable)) issues.add("scopesAvailable must be an array of strings");
        Object defaultScopes = in.get("defaultScopes");
        if (!isStringArray(defaultScopes)) issues.add("defaultScopes must be an array of strings");
        String[] listNames = {"scopesAvailable", "defaultScopes"};
        Object[] lists = {scopesAvailable, defaultScopes};
        for (int i = 0; i < 2; i++) {
            if (isStringArray(lists[i])) {
                List<String> list = strings(lists[i]);
                boolean bad = false;
                for (String s : list) if (s.isEmpty() || JsText.hasSpaceOrComma(s)) { bad = true; break; }
                if (bad) issues.add(listNames[i] + " entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)");
                if (new LinkedHashSet<>(list).size() != list.size()) issues.add(listNames[i] + " must not contain duplicates");
            }
        }
        if (isStringArray(scopesAvailable) && isStringArray(defaultScopes) && !strings(scopesAvailable).isEmpty()) {
            Set<String> available = new LinkedHashSet<>(strings(scopesAvailable));
            List<String> missing = new ArrayList<>();
            for (String s : strings(defaultScopes)) if (!available.contains(s)) missing.add(s);
            if (!missing.isEmpty()) issues.add("defaultScopes must be a subset of scopesAvailable (unknown: " + String.join(", ", missing) + ")");
        }

        Object refresh = in.get("refresh");
        if (!(refresh instanceof Map)) {
            issues.add("refresh must be an object");
        } else {
            Map<?, ?> rf = (Map<?, ?>) refresh;
            Object mode = rf.get("mode");
            if (!(mode instanceof String) || !(mode.equals("refresh_token") || mode.equals("none"))) issues.add("refresh.mode must be one of " + REFRESH_MODES);
            Object te = rf.get("tokenEndpoint");
            if (has(rf, "tokenEndpoint") && !isHttpsUrl(te)) issues.add("refresh.tokenEndpoint, when present, must be an https:// URL");
            if (has(rf, "supportsScopeNarrowing") && !(rf.get("supportsScopeNarrowing") instanceof Boolean)) issues.add("refresh.supportsScopeNarrowing must be a boolean");
            Object ep = rf.get("extraParams");
            if (has(rf, "extraParams") && !isStringRecord(ep)) issues.add("refresh.extraParams must be a string→string map");
            else if (isStringRecord(ep)) for (Object k : ((Map<?, ?>) ep).keySet()) if (RESERVED_TOKEN_PARAMS.contains(k)) issues.add("refresh.extraParams may not set '" + k + "': the request builder owns it");
        }

        Object tokenPlacement = in.get("tokenPlacement");
        if (!(tokenPlacement instanceof String) || !(tokenPlacement.equals("bearer") || tokenPlacement.equals("header") || tokenPlacement.equals("query"))) {
            issues.add("tokenPlacement must be one of " + PLACEMENTS);
        } else if (tokenPlacement.equals("header") && !isNonEmptyString(in.get("headerName"))) {
            issues.add("tokenPlacement 'header' requires a non-empty headerName");
        } else if (tokenPlacement.equals("query") && !isNonEmptyString(in.get("queryParam"))) {
            issues.add("tokenPlacement 'query' requires a non-empty queryParam");
        }
        Object headerName = in.get("headerName");
        if (headerName instanceof String && (!HEADER_NAME.matcher((String) headerName).matches() || FORBIDDEN_HEADERS.contains(((String) headerName).toLowerCase(Locale.ROOT)))) {
            issues.add("headerName '" + headerName + "' must be an HTTP token and not a protocol header");
        }
        Object queryParam = in.get("queryParam");
        if (queryParam instanceof String && !QUERY_NAME.matcher((String) queryParam).matches()) issues.add("queryParam '" + queryParam + "' must be a plain parameter name");
        Object sepRaw = in.get("scopeSeparator");
        if (sepRaw instanceof String && ((String) sepRaw).isEmpty()) issues.add("scopeSeparator must not be empty");

        if (has(in, "pkce") && !(in.get("pkce") instanceof Boolean)) issues.add("pkce must be a boolean");
        if (has(in, "scopeSeparator") && !(in.get("scopeSeparator") instanceof String)) issues.add("scopeSeparator must be a string");
        Object authParams = in.get("authParams");
        if (has(in, "authParams") && !isStringRecord(authParams)) issues.add("authParams must be a string→string map");
        else if (isStringRecord(authParams)) for (Object k : ((Map<?, ?>) authParams).keySet()) if (RESERVED_AUTHORIZE_PARAMS.contains(k)) issues.add("authParams may not set '" + k + "': the request builder owns it");
        Object clientAuth = in.get("clientAuth");
        if (has(in, "clientAuth") && !(clientAuth instanceof String && (clientAuth.equals("post") || clientAuth.equals("basic")))) issues.add("clientAuth must be one of " + CLIENT_AUTHS);

        Object requiredVars = in.get("requiredVars");
        if (has(in, "requiredVars") && !isStringArray(requiredVars)) issues.add("requiredVars must be an array of strings");
        // Every {var} that appears in a URL must be declared, and vice versa, so substitution can never silently leave a placeholder in a live request.
        if (isHttpsUrl(authorizeUrl) && isHttpsUrl(tokenUrl)) {
            Set<String> declared = new LinkedHashSet<>(isStringArray(requiredVars) ? strings(requiredVars) : List.<String>of());
            Set<String> used = new LinkedHashSet<>(urlVars((String) authorizeUrl));
            used.addAll(urlVars((String) tokenUrl));
            for (String v : used) if (!declared.contains(v)) issues.add("url uses '{" + v + "}' but requiredVars does not declare it");
            for (String v : declared) if (!used.contains(v)) issues.add("requiredVars declares '" + v + "' but no URL uses '{" + v + "}'");
        }

        if (has(in, "docsUrl") && !(in.get("docsUrl") instanceof String)) issues.add("docsUrl must be a string");

        if (!issues.isEmpty()) return new ManifestValidation(false, null, issues);
        return new ManifestValidation(true, freezeManifest(in), List.of());
    }

    /** Build a {@link ProviderManifest} from an already-validated record, copying only known fields. */
    private static ProviderManifest freezeManifest(Map<?, ?> in) {
        ProviderManifest m = new ProviderManifest();
        Map<?, ?> rf = in.get("refresh") instanceof Map ? (Map<?, ?>) in.get("refresh") : new LinkedHashMap<Object, Object>();
        m.refresh.mode = "none".equals(rf.get("mode")) ? "none" : "refresh_token";
        if (rf.get("tokenEndpoint") instanceof String) m.refresh.tokenEndpoint = (String) rf.get("tokenEndpoint");
        if (rf.get("supportsScopeNarrowing") instanceof Boolean) m.refresh.supportsScopeNarrowing = (Boolean) rf.get("supportsScopeNarrowing");
        if (isStringRecord(rf.get("extraParams"))) m.refresh.extraParams = stringMap(rf.get("extraParams"));

        m.id = in.get("id") instanceof String ? (String) in.get("id") : "";
        m.displayName = in.get("displayName") instanceof String ? (String) in.get("displayName") : "";
        m.authorizeUrl = in.get("authorizeUrl") instanceof String ? (String) in.get("authorizeUrl") : "";
        m.tokenUrl = in.get("tokenUrl") instanceof String ? (String) in.get("tokenUrl") : "";
        m.scopesAvailable = isStringArray(in.get("scopesAvailable")) ? strings(in.get("scopesAvailable")) : new ArrayList<>();
        m.defaultScopes = isStringArray(in.get("defaultScopes")) ? strings(in.get("defaultScopes")) : new ArrayList<>();
        Object tp = in.get("tokenPlacement");
        m.tokenPlacement = "header".equals(tp) ? "header" : "query".equals(tp) ? "query" : "bearer";
        if (in.get("pkce") instanceof Boolean) m.pkce = (Boolean) in.get("pkce");
        if (in.get("scopeSeparator") instanceof String) m.scopeSeparator = (String) in.get("scopeSeparator");
        if (isStringRecord(in.get("authParams"))) m.authParams = stringMap(in.get("authParams"));
        Object ca = in.get("clientAuth");
        if ("post".equals(ca) || "basic".equals(ca)) m.clientAuth = (String) ca;
        if (in.get("headerName") instanceof String) m.headerName = (String) in.get("headerName");
        if (in.get("queryParam") instanceof String) m.queryParam = (String) in.get("queryParam");
        if (isStringArray(in.get("requiredVars"))) m.requiredVars = strings(in.get("requiredVars"));
        if (in.get("docsUrl") instanceof String) m.docsUrl = (String) in.get("docsUrl");
        return m;
    }

    /** Validate {@code input}, returning the manifest or throwing {@link ManifestValidationError}. */
    public static ProviderManifest assertManifest(Object input) {
        ManifestValidation r = validateManifest(input);
        if (!r.ok) throw new ManifestValidationError(r.issues);
        return r.manifest;
    }

    /** A digest of a manifest (SHA-256 over canonical JSON). Pin the digest of a manifest you reviewed: a registry given it refuses a manifest that has since changed. */
    public static String manifestDigest(ProviderManifest manifest) { return Pca.hashCanonical(manifest.toMap()); }
}
