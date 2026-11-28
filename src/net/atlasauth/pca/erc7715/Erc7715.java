package net.atlasauth.pca.erc7715;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.oauth.JsVal;

/**
 * ERC-7715 ({@code wallet_requestExecutionPermissions}) for PCA grants: pure mapping and verification, no chain access and no redemption through a
 * delegation manager. The mapping covers the two permission names the draft ERC shows ({@code native-token-allowance} with {@code data.allowance},
 * and {@code erc20-token-allowance}, whose {@code {tokenAddress, allowance}} data is a PCA profile, not from the ERC). A wallet may narrow a permission
 * ({@code isAdjustmentAllowed}) but never widen it: amount, a later expiry, another token, chain, recipient or manager are all refused. There is no price
 * oracle: the caller states an exact integer ratio {@code baseUnitsPerMinor}. Values are parsed JSON (Map, List, String, Boolean, {@link Json.Num}, null).
 */
public final class Erc7715 {
    private Erc7715() {}

    public static final String NATIVE = "native-token-allowance";
    public static final String ERC20 = "erc20-token-allowance";

    private static final Pattern HEX_ADDR = Pattern.compile("0x[0-9a-fA-F]{40}");
    private static final Pattern HEX_QTY = Pattern.compile("0x(0|[1-9a-fA-F][0-9a-fA-F]*)");
    private static final Pattern HEX_CTX = Pattern.compile("0x[0-9a-fA-F]+");
    private static final Pattern DEC = Pattern.compile("0|[1-9][0-9]*");
    private static final Object UNDEF = new Object();

    // ---- JavaScript value helpers --------------------------------------------------------------------------------------

    /** {@code o[k]}: UNDEF when absent; a null or undefined o throws (TypeError); a primitive or an array has no such member. */
    private static Object at(Object o, String k) {
        if (o == null || o == UNDEF) throw new IllegalStateException("TypeError: cannot read properties of null (reading '" + k + "')");
        return o instanceof Map && ((Map<?, ?>) o).containsKey(k) ? ((Map<?, ?>) o).get(k) : UNDEF;
    }

    /** JavaScript {@code String(v)}. */
    private static String str(Object v) {
        if (v == UNDEF) return "undefined";
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = JsVal.num(v);
        if (d != null) return AttestCommon.jsNumString(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) sb.append(','); first = false; if (x != null && x != UNDEF) sb.append(str(x)); }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** {@code s.toLowerCase()}: a non-string has no such method (TypeError). */
    private static String lower(Object s) {
        if (!(s instanceof String)) throw new IllegalStateException("TypeError: toLowerCase is not a function");
        return ((String) s).toLowerCase(Locale.ROOT);
    }

    /** {@code Number.isSafeInteger} excluding nothing: -0 counts, as in the reference. */
    private static boolean safeInteger(Object o) {
        Double d = JsVal.num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.floor(d) && Math.abs(d) <= 9007199254740991.0;
    }

    private static boolean isNegZero(Object o) { Double d = JsVal.num(o); return d != null && d == 0.0 && Double.doubleToRawLongBits(d) != 0L; }

    private static boolean test(Pattern p, Object v) { return p.matcher(str(v)).matches(); }

    private static boolean jsSpace(char c) { return AttestCommon.isJsSpace(c); }

    /** {@code BigInt(v)}: a string (trimmed; empty is 0; 0x / 0o / 0b literals; a signed decimal), an integral number or a boolean; anything else throws. */
    private static BigInteger bigInt(Object v) {
        if (v instanceof List) v = str(v); // ToPrimitive of an array is its join text
        if (v instanceof Boolean) return (Boolean) v ? BigInteger.ONE : BigInteger.ZERO;
        if (v instanceof String) {
            String s = (String) v;
            int a = 0, b = s.length();
            while (a < b && jsSpace(s.charAt(a))) a++;
            while (b > a && jsSpace(s.charAt(b - 1))) b--;
            s = s.substring(a, b);
            if (s.isEmpty()) return BigInteger.ZERO;
            try {
                if (s.matches("0[xX][0-9a-fA-F]+")) return new BigInteger(s.substring(2), 16);
                if (s.matches("0[oO][0-7]+")) return new BigInteger(s.substring(2), 8);
                if (s.matches("0[bB][01]+")) return new BigInteger(s.substring(2), 2);
                if (s.matches("[+-]?[0-9]+")) return new BigInteger(s.startsWith("+") ? s.substring(1) : s);
            } catch (NumberFormatException e) { /* falls through */ }
            throw new IllegalArgumentException("SyntaxError: cannot convert " + s + " to a BigInt");
        }
        Double d = JsVal.num(v);
        if (d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.floor(d)) return new java.math.BigDecimal(d).toBigInteger();
        throw new IllegalArgumentException("TypeError: cannot convert to a BigInt");
    }

    private static String hexOf(BigInteger n) { return "0x" + n.toString(16); }

    // ---- request -------------------------------------------------------------------------------------------------------

    /**
     * Map a grant's money envelope to a permission request. {@code g}: {@code grantDigest}, {@code capMinor} (cumulative cap, integer minor units),
     * {@code expiresAtSec}. {@code o}: {@code chainId} (a {@link BigInteger}), {@code sessionAccount}, optional {@code tokenAddress} (absent: native token),
     * {@code baseUnitsPerMinor} (exact decimal-integer ratio), optional {@code from}, optional {@code isAdjustmentAllowed} (default true).
     * Throws IllegalArgumentException on a bad envelope, address, ratio or chain.
     */
    public static Map<String, Object> grantToPermissionRequest(Map<String, Object> g, Map<String, Object> o) {
        Object cap = at(g, "capMinor"), exp = at(g, "expiresAtSec");
        if (!safeInteger(cap) || JsVal.num(cap) <= 0 || !safeInteger(exp) || JsVal.num(exp) <= 0) throw new IllegalArgumentException("grantToPermissionRequest: bad envelope");
        Object session = at(o, "sessionAccount"), from = at(o, "from"), token = at(o, "tokenAddress");
        if (!test(HEX_ADDR, session) || (from != UNDEF && !test(HEX_ADDR, from)) || (token != UNDEF && !test(HEX_ADDR, token))) throw new IllegalArgumentException("grantToPermissionRequest: bad address");
        Object ratio = at(o, "baseUnitsPerMinor");
        if (!test(DEC, ratio) || "0".equals(ratio)) throw new IllegalArgumentException("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string");
        Object chain = o.get("chainId");
        if (!(chain instanceof BigInteger) || ((BigInteger) chain).signum() <= 0) throw new IllegalArgumentException("grantToPermissionRequest: bad chain");
        String allowance = hexOf(new java.math.BigDecimal(JsVal.num(cap)).toBigInteger().multiply(bigInt(ratio)));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("chainId", hexOf((BigInteger) chain));
        if (from != UNDEF) out.put("from", from);
        out.put("to", session);
        Object adj = o.get("isAdjustmentAllowed") != null ? o.get("isAdjustmentAllowed") : Boolean.TRUE;
        Map<String, Object> data = new LinkedHashMap<>();
        if (token != UNDEF) data.put("tokenAddress", token);
        data.put("allowance", allowance);
        Map<String, Object> permission = new LinkedHashMap<>();
        permission.put("type", token != UNDEF ? ERC20 : NATIVE);
        permission.put("isAdjustmentAllowed", adj);
        permission.put("data", data);
        out.put("permission", permission);
        Map<String, Object> ruleData = new LinkedHashMap<>();
        ruleData.put("timestamp", exp);
        Map<String, Object> rule = new LinkedHashMap<>();
        rule.put("type", "expiry");
        rule.put("data", ruleData);
        out.put("rules", new ArrayList<Object>(List.of(rule)));
        return out;
    }

    /**
     * Does the wallet's {@code wallet_getSupportedExecutionPermissions} result (keyed by permission type, with {@code chainIds} and {@code ruleTypes} or the draft's
     * other spelling {@code rulesTypes}) cover this request: its permission type, its chain, and every rule type. Pure; the caller made the RPC. Never throws.
     */
    @SuppressWarnings("unchecked")
    public static boolean supportsRequest(Object supported, Object req) {
        try {
            Object type = at(at(req, "permission"), "type");
            Object s = supported instanceof Map ? (((Map<String, Object>) supported).containsKey(str(type)) ? ((Map<String, Object>) supported).get(str(type)) : UNDEF) : at(supported, str(type));
            if (s == UNDEF) return false;
            Object chainIds = at(s, "chainIds");
            if (!(chainIds instanceof List)) return false;
            String want = lower(at(req, "chainId"));
            boolean found = false;
            for (Object c : (List<Object>) chainIds) if (lower(c).equals(want)) found = true; // every element is lowered first: a non-string element throws
            if (!found) return false;
            Object rt = at(s, "ruleTypes");
            if (rt == UNDEF || rt == null) rt = at(s, "rulesTypes");
            Object rules = at(req, "rules");
            if (rules == UNDEF || rules == null) return true;
            if (!(rules instanceof List)) return false; // no every() on anything else
            for (Object r : (List<Object>) rules) {
                if (!(rt instanceof List)) return false;
                Object t = at(r, "type");
                boolean has = false;
                for (Object x : (List<Object>) rt) if (x != null && t != UNDEF && x.equals(t)) has = true;
                if (!has) return false;
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The params of {@code wallet_revokeExecutionPermission}. */
    public static Map<String, Object> revokeParams(Object context) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("permissionContext", context);
        return m;
    }

    // ---- verification --------------------------------------------------------------------------------------------------

    /** {@code allowedManagers}: the delegation managers the operator trusts for the chain (a list of strings, compared lower-case); {@code contextOwner}: the grant digest a context handle is already bound to (null: unbound). */
    public static final class Options {
        public Object allowedManagers;
        public Function<String, Object> contextOwner;
    }

    private static boolean strictEq(Object a, Object b) {
        if (a == UNDEF || b == UNDEF) return a == b;
        if (a == null || b == null) return a == b;
        if (a instanceof String && b instanceof String) return a.equals(b);
        if (a instanceof Boolean && b instanceof Boolean) return a.equals(b);
        Double x = JsVal.num(a), y = JsVal.num(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    /**
     * Verify what the wallet actually granted against the request sent and the grant. Returns null when the permission is within the grant, else a reason
     * ({@code response_malformed}, {@code context_malformed}, {@code context_bound_to_other_grant}, {@code delegation_manager_not_allowed}, {@code chain_mismatch},
     * {@code recipient_mismatch}, {@code from_mismatch}, {@code permission_type_mismatch}, {@code token_mismatch}, {@code amount_malformed}, {@code amount_widened},
     * {@code adjustment_widened}, {@code expiry_missing}, {@code unknown_rule_type}, {@code duplicate_expiry}, {@code expiry_malformed}, {@code expiry_extended}).
     * A wallet may NARROW (isAdjustmentAllowed); it may never widen. Any exception while reading a hostile response is {@code response_malformed}. Never throws.
     */
    @SuppressWarnings("unchecked")
    public static String verifyGrantedPermission(Object g, Object sent, Object got, Options o) {
        try {
            if (!(got instanceof Map || got instanceof List)) return "response_malformed";
            Object perm = at(got, "permission");
            if (!(perm instanceof Map || perm instanceof List)) return "response_malformed";
            Object ctx = at(got, "context");
            if (!(ctx instanceof String) || !HEX_CTX.matcher((String) ctx).matches()) return "context_malformed";
            Object owner = o.contextOwner != null ? o.contextOwner.apply((String) ctx) : null;
            if (owner != null && !strictEq(owner, at(g, "grantDigest"))) return "context_bound_to_other_grant";
            Object dm = at(got, "delegationManager");
            if (!(dm instanceof String) || !HEX_ADDR.matcher((String) dm).matches()) return "delegation_manager_not_allowed";
            if (!(o.allowedManagers instanceof List)) throw new IllegalStateException("TypeError: allowedManagers.map is not a function");
            boolean allowed = false;
            String lowDm = lower(dm);
            for (Object m : (List<Object>) o.allowedManagers) if (lower(m).equals(lowDm)) allowed = true;
            if (!allowed) return "delegation_manager_not_allowed";
            if (!lower(str(at(got, "chainId"))).equals(lower(at(sent, "chainId")))) return "chain_mismatch";
            if (!lower(str(at(got, "to"))).equals(lower(at(sent, "to")))) return "recipient_mismatch";
            Object sentFrom = at(sent, "from");
            if (sentFrom != UNDEF && !lower(str(at(got, "from"))).equals(lower(sentFrom))) return "from_mismatch";
            Object sentPerm = at(sent, "permission");
            Object type = at(perm, "type");
            if (!strictEq(type, at(sentPerm, "type")) || (!NATIVE.equals(type) && !ERC20.equals(type))) return "permission_type_mismatch";
            Object d = at(perm, "data"), sd = at(sentPerm, "data");
            Object dTok = at(d, "tokenAddress"), sdTok = at(sd, "tokenAddress");
            if (!lower(str(dTok == UNDEF || dTok == null ? "" : dTok)).equals(lower(str(sdTok == UNDEF || sdTok == null ? "" : sdTok)))) return "token_mismatch";
            Object allowance = at(d, "allowance");
            if (!(allowance instanceof String) || !HEX_QTY.matcher((String) allowance).matches()) return "amount_malformed";
            if (bigInt(allowance).compareTo(bigInt(at(sd, "allowance"))) > 0) return "amount_widened";
            Object radj = at(perm, "isAdjustmentAllowed");
            if (!strictEq(radj, at(sentPerm, "isAdjustmentAllowed")) && Boolean.TRUE.equals(radj)) return "adjustment_widened";
            Object rules = at(got, "rules");
            if (!(rules instanceof List)) return "expiry_missing";
            Object expiry = UNDEF;
            for (Object rule : (List<Object>) rules) {
                Object rt = rule == null ? UNDEF : at(rule, "type");
                if (!"expiry".equals(rt)) return "unknown_rule_type";
                if (expiry != UNDEF) return "duplicate_expiry";
                expiry = at(at(rule, "data"), "timestamp");
                if (!safeInteger(expiry) || isNegZero(expiry)) return "expiry_malformed";
            }
            if (expiry == UNDEF) return "expiry_missing";
            Object gl = at(g, "expiresAtSec");
            // a grant expiry that is not a finite integer bounds nothing
            if (!(safeInteger(gl) && JsVal.num(expiry) <= JsVal.num(gl))) return "expiry_extended";
            return null;
        } catch (RuntimeException e) {
            return "response_malformed";
        }
    }

    /** {@code hashCanonical(grant)}: the digest a context is bound to. Throws for a value with no strict canonical form. */
    public static String grantDigestOf(Object grant) { return Pca.hashCanonical(grant); }
}
