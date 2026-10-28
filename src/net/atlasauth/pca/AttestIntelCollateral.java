package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Intel PCS collateral for the genuine DCAP TDX quote path: signed TCB info and QE identity (ECDSA-P256 over the exact bytes
 * of the signed value, under the TCB Signing certificate whose issuer chain ends at the pinned Intel SGX Root CA), the PCK
 * and Root CA CRLs, the evaluated TCB status and a status policy. Offline given the collateral bytes; fails closed on
 * missing, stale, malformed, unsigned or revoked collateral. The CRL reader ({@link #verifyCrl}) is shared with the NVIDIA
 * CRL checks. Port of the Go attest_intel_collateral.go.
 */
final class AttestIntelCollateral {
    private AttestIntelCollateral() {}

    static final List<String> TCB_STATUS_ORDER = Arrays.asList("UpToDate", "SWHardeningNeeded", "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded", "OutOfDate", "Revoked");

    static final List<String> DEFAULT_ACCEPTED_STATUSES = Arrays.asList("UpToDate", "SWHardeningNeeded");

    static final class Policy {
        List<String> acceptStatuses;
        boolean hasAccept;
        double minEval;
        boolean hasMinEval;
    }

    static final class Collateral {
        String tcbInfoJson = "";
        String tcbInfoChain = "";
        String qeIdentityJson = "";
        String qeIdentityChain = "";
        byte[] pckCrl;
        byte[] rootCrl;
    }

    static Collateral fromWire(Map<String, Object> m) {
        Collateral c = new Collateral();
        c.tcbInfoJson = str(m.get("tcbInfoJson"));
        c.tcbInfoChain = str(m.get("tcbInfoIssuerChainPem"));
        c.qeIdentityJson = str(m.get("qeIdentityJson"));
        c.qeIdentityChain = str(m.get("qeIdentityIssuerChainPem"));
        c.pckCrl = AttestAmd.evBytes(m, "pckCrlDer");
        c.rootCrl = AttestAmd.evBytes(m, "rootCrlDer");
        return c;
    }

    private static String str(Object v) { return v instanceof String ? (String) v : ""; }

    static final class Result {
        boolean ok;
        String reason = "";
        String status = "";
        List<String> advisoryIds = new ArrayList<>();
    }

    private static Result fail(String r) {
        Result x = new Result();
        x.reason = r;
        return x;
    }

    // ------------------------------------------------------------- CRL reading (lenient lengths, as the reference)

    static AttestDer.Tlv tlvLenient(byte[] b, int off, int limit) {
        if (off + 2 > limit) throw new AttestException("DER truncated");
        int tag = b[off] & 0xff;
        long l = b[off + 1] & 0xff;
        int p = off + 2;
        if ((l & 0x80) != 0) {
            int n = (int) (l & 0x7f);
            if (n == 0 || n > 4 || p + n > limit) throw new AttestException("DER bad length");
            l = 0;
            for (int i = 0; i < n; i++) l = l * 256 + (b[p + i] & 0xff);
            p += n;
        }
        if (p + l > limit) throw new AttestException("DER overrun");
        return new AttestDer.Tlv(tag, p, p + (int) l);
    }

    private static final Pattern UTC_TIME = Pattern.compile("([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z");
    private static final Pattern GEN_TIME = Pattern.compile("([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z");

    /** Date.UTC: the fields roll over; a year 0..99 means 19YY. */
    static long dateUtc(int y, int mo, int d, int h, int mi, int s) {
        if (y >= 0 && y <= 99) y += 1900;
        LocalDateTime t = LocalDateTime.of(y, 1, 1, 0, 0, 0).plusMonths(mo - 1L).plusDays(d - 1L).plusHours(h).plusMinutes(mi).plusSeconds(s);
        return t.toEpochSecond(ZoneOffset.UTC) * 1000L;
    }

    private static int g(Matcher m, int i) { return Integer.parseInt(m.group(i)); }

    static long crlTime(byte[] b, AttestDer.Tlv t) {
        String s = new String(b, t.start, t.end - t.start, StandardCharsets.ISO_8859_1);
        if (t.tag == 0x17) {
            Matcher m = UTC_TIME.matcher(s);
            if (!m.matches()) throw new AttestException("bad UTCTime");
            int yy = g(m, 1);
            int y = yy >= 50 ? 1900 + yy : 2000 + yy;
            return dateUtc(y, g(m, 2), g(m, 3), g(m, 4), g(m, 5), g(m, 6));
        }
        if (t.tag == 0x18) {
            Matcher m = GEN_TIME.matcher(s);
            if (!m.matches()) throw new AttestException("bad GeneralizedTime");
            return dateUtc(g(m, 1), g(m, 2), g(m, 3), g(m, 4), g(m, 5), g(m, 6));
        }
        throw new AttestException("not a DER time");
    }

    static final class ParsedCrl {
        byte[] tbs;
        long thisUpdate;
        long nextUpdate;
        boolean hasNext;
        Set<String> revoked = new HashSet<>();
        byte[] sigDer = new byte[0];
    }

    static ParsedCrl parseCrl(byte[] der) {
        AttestDer.Tlv outer = tlvLenient(der, 0, der.length);
        if (outer.tag != 0x30 || outer.end != der.length) throw new AttestException("CRL: bad outer SEQUENCE");
        AttestDer.Tlv tbsT = tlvLenient(der, outer.start, outer.end);
        if (tbsT.tag != 0x30) throw new AttestException("CRL: bad TBSCertList");
        ParsedCrl crl = new ParsedCrl();
        crl.tbs = Arrays.copyOfRange(der, outer.start, tbsT.end);
        AttestDer.Tlv algT = tlvLenient(der, tbsT.end, outer.end);
        AttestDer.Tlv sigT = tlvLenient(der, algT.end, outer.end);
        if (sigT.tag != 0x03 || sigT.end != outer.end) throw new AttestException("CRL: bad signature");
        if (sigT.start + 1 <= sigT.end) crl.sigDer = Arrays.copyOfRange(der, sigT.start + 1, sigT.end);
        int p = tbsT.start;
        AttestDer.Tlv t = tlvLenient(der, p, tbsT.end);
        if (t.tag == 0x02) {
            p = t.end;
            t = tlvLenient(der, p, tbsT.end);
        }
        p = t.end; // signature AlgorithmIdentifier
        AttestDer.Tlv iss = tlvLenient(der, p, tbsT.end);
        if (iss.tag != 0x30) throw new AttestException("CRL: bad issuer");
        AttestDer.Tlv tu = tlvLenient(der, iss.end, tbsT.end);
        crl.thisUpdate = crlTime(der, tu);
        int q = tu.end;
        if (q < tbsT.end) {
            AttestDer.Tlv n = tlvLenient(der, q, tbsT.end);
            if (n.tag == 0x17 || n.tag == 0x18) {
                crl.nextUpdate = crlTime(der, n);
                crl.hasNext = true;
                q = n.end;
            }
            if (q < tbsT.end) {
                n = tlvLenient(der, q, tbsT.end);
                if (n.tag == 0x30) {
                    int e = n.start;
                    while (e < n.end) {
                        AttestDer.Tlv ent = tlvLenient(der, e, n.end);
                        AttestDer.Tlv ser = tlvLenient(der, ent.start, ent.end);
                        if (ser.tag != 0x02) throw new AttestException("CRL: bad revoked entry");
                        crl.revoked.add(AttestCommon.normSerial(AttestCommon.toHexLower(Arrays.copyOfRange(der, ser.start, ser.end))));
                        e = ent.end;
                    }
                }
            }
        }
        if (!crl.hasNext) throw new AttestException("CRL: missing nextUpdate");
        return crl;
    }

    /** verify('sha256', tbs, issuerKey, sig): ECDSA (DER) or RSA PKCS#1 v1.5 under the issuer key. */
    static boolean crlSigOk(byte[] tbs, byte[] sig, CertKey k) {
        PublicKey pk = k.pub;
        String alg;
        if (pk instanceof ECPublicKey) alg = "SHA256withECDSA";
        else if (pk instanceof RSAPublicKey) alg = "SHA256withRSA";
        else return false;
        try {
            Signature v = Signature.getInstance(alg);
            v.initVerify(pk);
            v.update(tbs);
            return v.verify(sig);
        } catch (java.security.GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** The outcome of {@link #verifyCrl}: the revoked serials (lowercase hex, no leading zeros), or the failure reason. */
    static final class CrlResult {
        final Set<String> revoked;
        final String reason;

        CrlResult(Set<String> revoked, String reason) {
            this.revoked = revoked;
            this.reason = reason;
        }
    }

    /** Verifies a DER CRL under the issuer key at nowMs. */
    static CrlResult verifyCrl(byte[] der, CertKey issuer, long nowMs) {
        ParsedCrl crl;
        try {
            crl = parseCrl(der);
        } catch (AttestException | IndexOutOfBoundsException e) {
            return new CrlResult(null, "CRL parse failed: " + AttestCommon.errMsg(e));
        }
        if (!crlSigOk(crl.tbs, crl.sigDer, issuer)) return new CrlResult(null, "CRL signature does not verify under the issuer");
        if (nowMs < crl.thisUpdate) return new CrlResult(null, "CRL thisUpdate is in the future");
        if (nowMs > crl.nextUpdate) return new CrlResult(null, "CRL is stale (nextUpdate passed)");
        return new CrlResult(crl.revoked, "");
    }

    // ------------------------------------------------------------- signed JSON documents

    private static int skipJsSpace(String s, int i) {
        while (i < s.length() && AttestCommon.isJsSpace(s.charAt(i))) i++;
        return i;
    }

    /** The exact source text of the JSON object following "&lt;name&gt;": in a top-level object, or null. */
    static String rawJsonObject(String text, String name) {
        int i = skipJsSpace(text, 0);
        if (i >= text.length() || text.charAt(i) != '{') return null;
        i = skipJsSpace(text, i + 1);
        String key = "\"" + name + "\"";
        if (!text.startsWith(key, i)) return null;
        i = skipJsSpace(text, i + key.length());
        if (i >= text.length() || text.charAt(i) != ':') return null;
        i = skipJsSpace(text, i + 1);
        if (i >= text.length() || text.charAt(i) != '{') return null;
        int start = i;
        int depth = 0;
        boolean inStr = false;
        for (; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (inStr) {
                if (ch == '\\') i++;
                else if (ch == '"') inStr = false;
            } else if (ch == '"') {
                inStr = true;
            } else if (ch == '{') {
                depth++;
            } else if (ch == '}') {
                depth--;
                if (depth == 0) return text.substring(start, i + 1);
            }
        }
        return null;
    }

    private static final Pattern SIG128 = Pattern.compile("[0-9a-fA-F]{128}");

    /** The outcome of {@link #verifySignedJson}: the body under name, or the failure text. */
    static final class SignedBody {
        final Map<String, Object> body;
        final String reason;

        SignedBody(Map<String, Object> body, String reason) {
            this.body = body;
            this.reason = reason;
        }
    }

    /** Verifies a PCS document: the body under name, or the failure text. */
    static SignedBody verifySignedJson(String text, String name, CertKey k) {
        String raw = rawJsonObject(text, name);
        if (raw == null) return new SignedBody(null, name + " not found / malformed");
        Object doc;
        try {
            doc = AttestCommon.jsonLenient(text.getBytes(StandardCharsets.UTF_8));
        } catch (AttestException e) {
            return new SignedBody(null, name + " document is not valid JSON");
        }
        Map<String, Object> top = AttestCommon.asRec(doc);
        Object sigv = top == null ? null : top.get("signature");
        String sig = sigv instanceof String ? (String) sigv : "";
        if (!SIG128.matcher(sig).matches()) return new SignedBody(null, name + " signature missing or malformed");
        if (!(k.pub instanceof ECPublicKey)
            || !AttestCommon.verifyRawECDSA((ECPublicKey) k.pub, AttestCommon.sha256Sum(raw.getBytes(StandardCharsets.UTF_8)), AttestCommon.hexDecode(sig))) {
            return new SignedBody(null, name + " signature does not verify under the TCB Signing certificate");
        }
        Map<String, Object> body = AttestCommon.asRec(top.get(name));
        if (body == null) return new SignedBody(null, name + " is not an object");
        return new SignedBody(body, "");
    }

    /** Date.parse for the ISO-8601 forms PCS documents use (epoch ms), or null. */
    static Long jsDateParse(String s) {
        try {
            return OffsetDateTime.parse(s).toInstant().toEpochMilli();
        } catch (DateTimeParseException e) {
            // fall through to the date-only form
        }
        try {
            return LocalDate.parse(s).atStartOfDay().toEpochSecond(ZoneOffset.UTC) * 1000L;
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    static String checkFresh(Map<String, Object> body, String what, long nowMs) {
        Object is = body.get("issueDate");
        Object ns = body.get("nextUpdate");
        Long issue = is instanceof String ? jsDateParse((String) is) : null;
        Long next = ns instanceof String ? jsDateParse((String) ns) : null;
        if (issue == null || next == null) return what + ": issueDate/nextUpdate missing";
        if (nowMs < issue) return what + ": issueDate is in the future";
        if (nowMs > next) return what + ": stale (nextUpdate passed)";
        return "";
    }

    // ------------------------------------------------------------- status evaluation

    static int statusRank(String s) { return TCB_STATUS_ORDER.indexOf(s); }

    static String asTcbStatus(Object v) { return v instanceof String && statusRank((String) v) >= 0 ? (String) v : null; }

    static String worstStatus(String a, String b) { return statusRank(a) >= statusRank(b) ? a : b; }

    static double[] svnList(Object v) {
        if (!(v instanceof List) || ((List<?>) v).size() != 16) return null;
        double[] out = new double[16];
        int i = 0;
        for (Object c : (List<?>) v) {
            Map<String, Object> rec = AttestCommon.asRec(c);
            if (rec == null) return null;
            Double f = AttestCommon.asFinite(rec.get("svn"));
            if (f == null) return null;
            out[i++] = f;
        }
        return out;
    }

    static byte[] hexBytesN(Object v, int n) {
        if (!(v instanceof String)) return null;
        String s = (String) v;
        if (s.length() != n * 2 || !AttestCommon.isHexChars(s)) return null;
        return AttestCommon.hexDecode(s);
    }

    static List<String> advisoryList(Map<String, Object> level) {
        List<String> out = new ArrayList<>();
        Object arr = level.get("advisoryIDs");
        if (!(arr instanceof List)) return out;
        for (Object x : (List<?>) arr) if (x instanceof String) out.add((String) x);
        return out;
    }

    static boolean maskedEq(byte[] value, byte[] mask, byte[] expected) {
        for (int i = 0; i < value.length; i++) if (((value[i] & mask[i]) ^ (expected[i] & mask[i])) != 0) return false;
        return true;
    }

    /** levels.find(l =&gt; isRecord(l) &amp;&amp; isRecord(l.tcb) &amp;&amp; typeof l.tcb.isvsvn === 'number' &amp;&amp; l.tcb.isvsvn &lt;= svn). */
    static Map<String, Object> findLevel(Object levels, double svn) {
        if (!(levels instanceof List)) return null;
        for (Object x : (List<?>) levels) {
            Map<String, Object> l = AttestCommon.asRec(x);
            if (l == null) continue;
            Map<String, Object> tcb = AttestCommon.asRec(l.get("tcb"));
            if (tcb == null) continue;
            Double f = AttestCommon.asFinite(tcb.get("isvsvn"));
            if (f != null && f <= svn) return l;
        }
        return null;
    }

    /** {platform, module, advisories, err}: err is null on success. */
    static final class TcbEval {
        String platform;
        String module;
        List<String> advisories = new ArrayList<>();
        String err;

        static TcbEval error(String e) {
            TcbEval t = new TcbEval();
            t.err = e;
            return t;
        }
    }

    private static TreeSet<String> utf8Set() { return new TreeSet<>(Json::compareUtf8); }

    static TcbEval evaluateTcb(Map<String, Object> info, byte[] pckSgx, int pckPcesvn, byte[] teeTcbSvn, byte[] mrSignerSeam, byte[] seamAttributes) {
        Object lv = info.get("tcbLevels");
        List<?> levels = lv instanceof List ? (List<?>) lv : new ArrayList<>();
        if (levels.isEmpty()) return TcbEval.error("TCB info has no tcbLevels");
        int minor = teeTcbSvn[1] & 0xff;
        String moduleStatus = "UpToDate";
        TreeSet<String> adv = utf8Set();
        Object modMrSigner;
        Object modAttr;
        Object modMask;
        if (minor > 0) {
            String id = String.format("TDX_%02X", minor);
            Map<String, Object> ident = null;
            Object ids = info.get("tdxModuleIdentities");
            if (ids instanceof List) {
                for (Object x : (List<?>) ids) {
                    Map<String, Object> r = AttestCommon.asRec(x);
                    if (r != null && id.equals(r.get("id"))) {
                        ident = r;
                        break;
                    }
                }
            }
            if (ident == null) return TcbEval.error("TDX module identity " + id + " not present in TCB info");
            modMrSigner = ident.get("mrsigner");
            modAttr = ident.get("attributes");
            modMask = ident.get("attributesMask");
            int svn0 = teeTcbSvn[0] & 0xff;
            Map<String, Object> hit = findLevel(ident.get("tcbLevels"), svn0);
            if (hit == null) return TcbEval.error("TDX module " + id + " SVN " + svn0 + " is below every known level");
            String st = asTcbStatus(hit.get("tcbStatus"));
            if (st == null) return TcbEval.error("TDX module level has an unknown tcbStatus");
            moduleStatus = st;
            adv.addAll(advisoryList(hit));
        } else {
            Map<String, Object> m = AttestCommon.asRec(info.get("tdxModule"));
            if (m == null) return TcbEval.error("TCB info missing tdxModule");
            modMrSigner = m.get("mrsigner");
            modAttr = m.get("attributes");
            modMask = m.get("attributesMask");
        }
        byte[] exMr = hexBytesN(modMrSigner, 48);
        byte[] exAttr = hexBytesN(modAttr, 8);
        byte[] mask = hexBytesN(modMask, 8);
        if (exMr == null || exAttr == null || mask == null) return TcbEval.error("TDX module identity fields malformed");
        if (!Arrays.equals(exMr, mrSignerSeam)) return TcbEval.error("TD report MRSIGNERSEAM does not match the TDX module identity");
        if (!maskedEq(seamAttributes, mask, exAttr)) return TcbEval.error("TD report SEAM attributes do not match the TDX module identity");
        int from = minor > 0 ? 2 : 0;
        for (Object x : levels) {
            Map<String, Object> l = AttestCommon.asRec(x);
            Map<String, Object> tcb = l == null ? null : AttestCommon.asRec(l.get("tcb"));
            if (tcb == null) return TcbEval.error("malformed TCB level");
            double[] sgx = svnList(tcb.get("sgxtcbcomponents"));
            double[] tdx = svnList(tcb.get("tdxtcbcomponents"));
            Double pce = AttestCommon.asFinite(tcb.get("pcesvn"));
            if (sgx == null || tdx == null || pce == null) return TcbEval.error("malformed TCB level components");
            String st = asTcbStatus(l.get("tcbStatus"));
            if (st == null) return TcbEval.error("TCB level has an unknown tcbStatus");
            boolean match = pckPcesvn >= pce;
            for (int i = 0; match && i < 16; i++) if ((pckSgx[i] & 0xff) < sgx[i]) match = false;
            for (int i = from; match && i < 16; i++) if ((teeTcbSvn[i] & 0xff) < tdx[i]) match = false;
            if (!match) continue;
            adv.addAll(advisoryList(l));
            TcbEval ok = new TcbEval();
            ok.platform = st;
            ok.module = moduleStatus;
            ok.advisories = new ArrayList<>(adv);
            return ok;
        }
        return TcbEval.error("platform TCB is below every level in the TCB info");
    }

    /** {status, advisories, err}: err is null on success. */
    static final class QeEval {
        String status;
        List<String> advisories = new ArrayList<>();
        String err;

        static QeEval error(String e) {
            QeEval q = new QeEval();
            q.err = e;
            return q;
        }
    }

    static QeEval evaluateQe(Map<String, Object> ident, byte[] qe) {
        if (!"TD_QE".equals(ident.get("id"))) return QeEval.error("QE identity id is not TD_QE");
        Double v = AttestCommon.asFinite(ident.get("version"));
        if (v == null || v != 2) return QeEval.error("unsupported QE identity version");
        byte[] miscsel = hexBytesN(ident.get("miscselect"), 4);
        byte[] miscMask = hexBytesN(ident.get("miscselectMask"), 4);
        byte[] attr = hexBytesN(ident.get("attributes"), 16);
        byte[] attrMask = hexBytesN(ident.get("attributesMask"), 16);
        byte[] mrsigner = hexBytesN(ident.get("mrsigner"), 32);
        Double prodId = AttestCommon.asFinite(ident.get("isvprodid"));
        if (miscsel == null || miscMask == null || attr == null || attrMask == null || mrsigner == null || prodId == null) {
            return QeEval.error("QE identity fields malformed");
        }
        if (qe.length != 384) return QeEval.error("QE report has wrong length");
        if (!maskedEq(Arrays.copyOfRange(qe, 16, 20), miscMask, miscsel)) return QeEval.error("QE MISCSELECT does not match the QE identity");
        if (!maskedEq(Arrays.copyOfRange(qe, 48, 64), attrMask, attr)) return QeEval.error("QE ATTRIBUTES do not match the QE identity");
        if (!Arrays.equals(Arrays.copyOfRange(qe, 128, 160), mrsigner)) return QeEval.error("QE MRSIGNER does not match the QE identity");
        int prod = (qe[256] & 0xff) | (qe[257] & 0xff) << 8;
        int isvsvn = (qe[258] & 0xff) | (qe[259] & 0xff) << 8;
        if ((double) prod != prodId) return QeEval.error("QE ISVPRODID does not match the QE identity");
        Map<String, Object> hit = findLevel(ident.get("tcbLevels"), isvsvn);
        if (hit == null) return QeEval.error("QE ISVSVN is below every known level");
        String st = asTcbStatus(hit.get("tcbStatus"));
        if (st == null) return QeEval.error("QE level has an unknown tcbStatus");
        QeEval ok = new QeEval();
        ok.status = st;
        ok.advisories = advisoryList(hit);
        return ok;
    }

    /** The outcome of {@link #signerKeyFromChain}: the leaf's key, or the failure text. */
    static final class SignerKey {
        final CertKey key;
        final String reason;

        SignerKey(CertKey key, String reason) {
            this.key = key;
            this.reason = reason;
        }
    }

    /**
     * Verifies a PCS issuer chain (leaf first) to the pinned root, validity at nowMs and that no certificate is on the Root
     * CA CRL.
     */
    static SignerKey signerKeyFromChain(String chainPem, String pin, long nowMs, Set<String> rootRevoked) {
        AttestIntel.PckChainResult chain = AttestIntel.verifyIntelPckChain(chainPem, pin, nowMs);
        if (chain.validity) return new SignerKey(null, "issuer chain certificate outside its validity period");
        if (!chain.ok || chain.leaf == null) return new SignerKey(null, "issuer chain invalid: " + chain.reason);
        try {
            for (String b : AttestCommon.pemCertBlocks(chainPem)) {
                AttCert c = AttestCert.certFromPem(b);
                if (!AttestDer.derValidAt(c.raw, nowMs, 0)) return new SignerKey(null, "issuer chain certificate outside its validity period");
                if (rootRevoked.contains(c.serialHex())) return new SignerKey(null, "issuer chain certificate is revoked by the Intel Root CA CRL");
            }
            return new SignerKey(AttestCert.keyOfCert(chain.leaf), "");
        } catch (AttestException e) {
            return new SignerKey(null, "collateral verification error (fail closed): " + AttestCommon.errMsg(e));
        }
    }

    /** Verifies the quote and then its PCS collateral at nowMs: the evaluated TCB status and the policy decision. */
    static Result verifyIntelTdxCollateral(byte[] quote, Collateral c, long nowMs, Policy pol, String pin, boolean allowDebug) {
        if (c == null || c.tcbInfoJson.isEmpty() || c.qeIdentityJson.isEmpty() || c.pckCrl == null || c.pckCrl.length == 0
            || c.rootCrl == null || c.rootCrl.length == 0 || c.tcbInfoChain.isEmpty() || c.qeIdentityChain.isEmpty()) {
            return fail("collateral incomplete (fail closed)");
        }
        AttestIntel.TdxResult base = AttestIntel.verifyGenuineTdxQuote(quote, pin, nowMs, null, allowDebug);
        if (!base.ok || base.pck == null || base.fmspc.isEmpty()) return fail("quote invalid: " + base.reason);
        AttestIntel.DcapQuote q;
        CrlResult rootCrl;
        CrlResult pckCrl;
        AttCert leaf = null;
        AttCert ca = null;
        AttCert root = null;
        try {
            q = AttestIntel.parseDcapQuote(quote);
            List<AttCert> quoteCerts = new ArrayList<>();
            for (String b : AttestCommon.pemCertBlocks(q.pckChainPem)) quoteCerts.add(AttestCert.certFromPem(b));
            for (AttCert x : quoteCerts) if (!AttestDer.derValidAt(x.raw, nowMs, 0)) return fail("PCK chain certificate outside its validity period");
            for (AttCert x : quoteCerts) {
                boolean issues = false;
                for (AttCert y : quoteCerts) if (Arrays.equals(y.rawIssuer, x.rawSubject)) issues = true;
                if (!issues) {
                    leaf = x;
                    break;
                }
            }
            if (leaf == null) return fail("PCK leaf not found");
            for (AttCert x : quoteCerts) {
                if (Arrays.equals(x.rawSubject, leaf.rawIssuer)) {
                    ca = x;
                    break;
                }
            }
            if (ca == null) return fail("PCK CA not found in the quote chain");
            for (AttCert x : quoteCerts) {
                if (x.selfIssued()) {
                    root = x;
                    break;
                }
            }
            if (root == null) return fail("Intel root not found in the quote chain");
            CertKey rootKey = AttestCert.keyOfCert(root);
            CertKey caKey = AttestCert.keyOfCert(ca);
            rootCrl = verifyCrl(c.rootCrl, rootKey, nowMs);
            if (!rootCrl.reason.isEmpty()) return fail("Intel Root CA CRL: " + rootCrl.reason);
            pckCrl = verifyCrl(c.pckCrl, caKey, nowMs);
            if (!pckCrl.reason.isEmpty()) return fail("PCK CRL: " + pckCrl.reason);
        } catch (AttestException e) {
            return fail("collateral verification error (fail closed): " + AttestCommon.errMsg(e));
        }
        if (rootCrl.revoked.contains(ca.serialHex())) return fail("PCK CA certificate is revoked by the Intel Root CA CRL");
        if (pckCrl.revoked.contains(leaf.serialHex())) return fail("PCK leaf certificate is revoked by the PCK CRL");

        SignerKey tcbKey = signerKeyFromChain(c.tcbInfoChain, pin, nowMs, rootCrl.revoked);
        if (!tcbKey.reason.isEmpty()) return fail("TCB info: " + tcbKey.reason);
        SignedBody info = verifySignedJson(c.tcbInfoJson, "tcbInfo", tcbKey.key);
        if (!info.reason.isEmpty()) return fail("TCB info: " + info.reason);
        String stale = checkFresh(info.body, "TCB info", nowMs);
        if (!stale.isEmpty()) return fail(stale);
        if (!"TDX".equals(info.body.get("id"))) return fail("TCB info is not a TDX v3 document");
        Double ver = AttestCommon.asFinite(info.body.get("version"));
        if (ver == null || ver != 3) return fail("TCB info is not a TDX v3 document");
        Object fm = info.body.get("fmspc");
        if (!(fm instanceof String) || !((String) fm).toLowerCase(java.util.Locale.ROOT).equals(base.fmspc)) {
            return fail("TCB info FMSPC does not match the quote PCK");
        }

        SignerKey qeKey = signerKeyFromChain(c.qeIdentityChain, pin, nowMs, rootCrl.revoked);
        if (!qeKey.reason.isEmpty()) return fail("QE identity: " + qeKey.reason);
        SignedBody qeBody = verifySignedJson(c.qeIdentityJson, "enclaveIdentity", qeKey.key);
        if (!qeBody.reason.isEmpty()) return fail("QE identity: " + qeBody.reason);
        stale = checkFresh(qeBody.body, "QE identity", nowMs);
        if (!stale.isEmpty()) return fail(stale);

        Double fi = AttestCommon.asFinite(info.body.get("tcbEvaluationDataNumber"));
        Double fq = AttestCommon.asFinite(qeBody.body.get("tcbEvaluationDataNumber"));
        double infoNum = fi == null ? -1 : fi;
        double qeNum = fq == null ? -1 : fq;
        if (infoNum < 0 || qeNum < 0) return fail("tcbEvaluationDataNumber missing");
        if (pol != null && pol.hasMinEval && (infoNum < pol.minEval || qeNum < pol.minEval)) return fail("tcbEvaluationDataNumber below policy minimum");

        byte[] body = q.tdReportBody;
        TcbEval tcb = evaluateTcb(info.body, base.pck.sgx, base.pck.pcesvn, Arrays.copyOfRange(body, 0, 16),
            Arrays.copyOfRange(body, 64, 112), Arrays.copyOfRange(body, 112, 120));
        if (tcb.err != null) return fail("TCB evaluation: " + tcb.err);
        // the PCK leaf's own issued TCB is the one the quote verification extracted from the verified chain
        QeEval qe = evaluateQe(qeBody.body, q.qeReportBody);
        if (qe.err != null) return fail("QE identity: " + qe.err);
        String status = worstStatus(worstStatus(tcb.platform, tcb.module), qe.status);
        TreeSet<String> ids = utf8Set();
        ids.addAll(tcb.advisories);
        ids.addAll(qe.advisories);
        Result res = new Result();
        res.status = status;
        res.advisoryIds = new ArrayList<>(ids);
        List<String> accepted = pol != null && pol.hasAccept ? pol.acceptStatuses : DEFAULT_ACCEPTED_STATUSES;
        if (!accepted.contains(status)) {
            res.reason = "TCB status " + status + " is not accepted by policy";
            return res;
        }
        res.ok = true;
        return res;
    }
}
