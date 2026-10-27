package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * NVIDIA GPU-CC collateral: Reference Integrity Manifests (SWID/CoRIM XML, enveloped XMLDSig, strict profile), the golden
 * measurement comparison with NVIDIA's merge / alternatives / NVDEC0 rules, the driver / VBIOS version binding, certificate
 * revocation through CRLs (here) and OCSP ({@link AttestNvidiaOcsp}), and a firmware policy. Fetching is never automatic: the
 * RIMs, CRLs and OCSP responses arrive with the evidence. Same checks, order and reason text as the reference. Port of the Go
 * attest_nvidia_rim.go.
 */
final class AttestNvidiaRim {
    private AttestNvidiaRim() {}

    static final String NS_DSIG = "http://www.w3.org/2000/09/xmldsig#";
    static final String ALG_C14N11 = "http://www.w3.org/2006/12/xml-c14n11";
    static final String ALG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    static final String ALG_ECDSA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    static final String ALG_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    static final int NVDEC0_OFF = 0x55;
    static final int NVDEC_BLOCK = 35;

    /** One golden measurement of a RIM. */
    static final class Golden {
        final long index;
        final boolean active;
        final long alternatives;
        final long size;
        final List<String> hashes;

        Golden(long index, boolean active, long alternatives, long size, List<String> hashes) {
            this.index = index;
            this.active = active;
            this.alternatives = alternatives;
            this.size = size;
            this.hashes = hashes;
        }
    }

    /** A verified manifest: product, colloquial version and golden measurements by index. */
    static final class Rim {
        final String product;
        final String version;
        final Map<Long, Golden> golden;

        Rim(String product, String version, Map<Long, Golden> golden) {
            this.product = product;
            this.version = version;
            this.golden = golden;
        }
    }

    /** A verified RIM, or the failure reason. */
    static final class RimResult {
        final Rim rim;
        final String reason;

        RimResult(Rim rim, String reason) {
            this.rim = rim;
            this.reason = reason;
        }
    }

    private static RimResult fail(String r) { return new RimResult(null, r); }

    static String stripJsSpace(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) if (!AttestCommon.isJsSpace(s.charAt(i))) sb.append(s.charAt(i));
        return sb.toString();
    }

    static String pemOfDerB64(String b64) {
        String body = stripJsSpace(b64);
        List<String> lines = new ArrayList<>();
        for (int i = 0; i < body.length(); i += 64) lines.add(body.substring(i, Math.min(i + 64, body.length())));
        return "-----BEGIN CERTIFICATE-----\n" + String.join("\n", lines) + "\n-----END CERTIFICATE-----";
    }

    private static final Pattern HASH_ATTR = Pattern.compile("Hash[0-9]+");
    private static final Pattern LOWER_HEX = Pattern.compile("[0-9a-f]+");

    private static String algOf(List<AttestXml.Node> els) { return els.isEmpty() ? "" : els.get(0).attr("Algorithm"); }

    /** verifyNvidiaRim: a RIM document's golden measurements, or the failure reason. */
    static RimResult verifyRim(String xml, List<String> rimPins, long nowMs) {
        if (xml == null || xml.isEmpty() || xml.length() > 4_000_000) return fail("RIM: empty or oversized document");
        if (rimPins.isEmpty()) return fail("RIM: no pinned RIM root configured");
        AttestXml.Doc doc;
        try {
            doc = AttestXml.parseXml(xml);
        } catch (AttestException e) {
            return fail("RIM: verification error (fail closed): " + AttestCommon.errMsg(e));
        }
        if (!doc.violation.isEmpty()) return fail("RIM: " + doc.violation);
        AttestXml.Node root = doc.root;
        if (!root.local.equals("SoftwareIdentity")) return fail("RIM: root element is not SoftwareIdentity");
        if (root.descendantsNs(NS_DSIG, "Signature") != 1) return fail("RIM: expected exactly one Signature element");
        List<AttestXml.Node> sigs = root.elementChildrenNs(NS_DSIG, "Signature");
        if (sigs.size() != 1) return fail("RIM: the Signature must be a direct child of the root");
        AttestXml.Node sig = sigs.get(0);
        List<AttestXml.Node> signedInfo = sig.elementChildrenNs(NS_DSIG, "SignedInfo");
        if (signedInfo.size() != 1) return fail("RIM: expected exactly one SignedInfo");
        AttestXml.Node si = signedInfo.get(0);
        if (!algOf(si.elementChildrenNs(NS_DSIG, "CanonicalizationMethod")).equals(ALG_C14N11)) return fail("RIM: CanonicalizationMethod must be C14N 1.1");
        if (!algOf(si.elementChildrenNs(NS_DSIG, "SignatureMethod")).equals(ALG_ECDSA384)) return fail("RIM: SignatureMethod must be ECDSA-SHA384");
        List<AttestXml.Node> refs = si.elementChildrenNs(NS_DSIG, "Reference");
        if (refs.size() != 1) return fail("RIM: expected exactly one Reference");
        AttestXml.Node ref = refs.get(0);
        if (!ref.attr("URI").isEmpty()) return fail("RIM: Reference URI must be \"\" (the whole document)");
        AttestXml.Node holder = ref;
        List<AttestXml.Node> ts = ref.elementChildrenNs(NS_DSIG, "Transforms");
        if (!ts.isEmpty()) holder = ts.get(0);
        List<String> transforms = new ArrayList<>();
        for (AttestXml.Node t : holder.elementChildrenNs(NS_DSIG, "Transform")) transforms.add(t.attr("Algorithm"));
        if (transforms.size() != 2 || !transforms.get(0).equals(ALG_ENVELOPED) || !transforms.get(1).equals(ALG_C14N11)) {
            return fail("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]");
        }
        if (!algOf(ref.elementChildrenNs(NS_DSIG, "DigestMethod")).equals(ALG_SHA384)) return fail("RIM: DigestMethod must be SHA-384");
        String digestValue = "";
        String sigValueB64 = "";
        List<AttestXml.Node> d = ref.elementChildrenNs(NS_DSIG, "DigestValue");
        if (!d.isEmpty()) digestValue = stripJsSpace(d.get(0).textContent());
        d = sig.elementChildrenNs(NS_DSIG, "SignatureValue");
        if (!d.isEmpty()) sigValueB64 = stripJsSpace(d.get(0).textContent());
        if (digestValue.isEmpty() || sigValueB64.isEmpty()) return fail("RIM: missing DigestValue / SignatureValue");

        List<String> certB64 = new ArrayList<>();
        List<AttestXml.Node> ki = sig.elementChildrenNs(NS_DSIG, "KeyInfo");
        if (!ki.isEmpty()) {
            List<AttestXml.Node> xd = ki.get(0).elementChildrenNs(NS_DSIG, "X509Data");
            if (!xd.isEmpty()) for (AttestXml.Node c : xd.get(0).elementChildrenNs(NS_DSIG, "X509Certificate")) certB64.add(c.textContent());
        }
        if (certB64.isEmpty()) return fail("RIM: no signer certificates in KeyInfo");
        List<String> pems = new ArrayList<>();
        for (String c : certB64) pems.add(pemOfDerB64(c));
        AttestNvidia.Chain chain = AttestNvidia.verifyDeviceChain(String.join("\n", pems), rimPins, nowMs);
        if (chain.certs == null) return fail("RIM signer chain: " + chain.reason);

        String siCanon = AttestXml.canonicalize(si, si.parent.scope(), null);
        byte[] sigRaw = AttestCommon.nodeB64(sigValueB64);
        if (sigRaw.length != 96) return fail("RIM: SignatureValue is not a 96-byte P-384 signature");
        boolean ok;
        try {
            CertKey lk = AttestCert.keyOfCert(chain.certs.get(0));
            ok = lk.pub instanceof ECPublicKey
                && AttestCommon.verifyRawECDSA((ECPublicKey) lk.pub, AttestCommon.sha384Sum(siCanon.getBytes(StandardCharsets.UTF_8)), sigRaw);
        } catch (AttestException e) {
            ok = false;
        }
        if (!ok) return fail("RIM: SignedInfo signature does not verify under the signer certificate");

        String canon = AttestXml.canonicalize(root, new HashMap<>(), sig);
        if (!Base64.getEncoder().encodeToString(AttestCommon.sha384Sum(canon.getBytes(StandardCharsets.UTF_8))).equals(digestValue)) {
            return fail("RIM: document digest does not match the signed DigestValue");
        }

        AttestXml.Node meta = null;
        AttestXml.Node payload = null;
        for (AttestXml.Node c : root.elementChildren()) {
            if (meta == null && c.local.equals("Meta")) meta = c;
            if (payload == null && c.local.equals("Payload")) payload = c;
        }
        if (meta == null || payload == null) return fail("RIM: missing Meta / Payload");
        Map<Long, Golden> golden = new HashMap<>();
        for (AttestXml.Node r : payload.elementChildren()) {
            if (!r.local.equals("Resource") || !r.attr("type").equals("Measurement")) continue;
            double index = AttestNvidia.jsNumber(r.attr("index"));
            double alts = AttestNvidia.jsNumber(r.attr("alternatives"));
            double size = AttestNvidia.jsNumber(r.attr("size"));
            List<AttestXml.Attr> hs = new ArrayList<>();
            for (AttestXml.Attr a : r.attrs) if (HASH_ATTR.matcher(a.local).matches()) hs.add(a);
            hs.sort((a, b) -> Double.compare(AttestNvidia.jsNumber(a.local.substring(4)), AttestNvidia.jsNumber(b.local.substring(4)))); // stable
            if (!AttestNvidia.isJsInteger(index) || index < 0 || !AttestNvidia.isJsInteger(alts) || alts < 1 || !AttestNvidia.isJsInteger(size) || size < 1) {
                return fail("RIM: malformed Measurement resource");
            }
            List<String> hashes = new ArrayList<>();
            for (AttestXml.Attr a : hs) hashes.add(a.value.toLowerCase(Locale.ROOT));
            boolean bad = hashes.size() != alts;
            for (String h : hashes) if (!LOWER_HEX.matcher(h).matches() || h.length() != size * 2) bad = true;
            long idx = (long) index;
            if (bad) return fail("RIM: Measurement " + idx + " hash list is inconsistent with alternatives/size");
            if (golden.containsKey(idx)) return fail("RIM: duplicate Measurement index " + idx);
            golden.put(idx, new Golden(idx, r.attr("active").toLowerCase(Locale.ROOT).equals("true"), (long) alts, (long) size, hashes));
        }
        if (golden.isEmpty()) return fail("RIM: no measurements");
        return new RimResult(new Rim(meta.attr("product"), meta.attr("colloquialVersion"), golden), "");
    }

    // ------------------------------------------------------------- RIM ids named by the (signed) GPU report

    /** The RIM ids and versions a report names. */
    static final class RimIds {
        String chip;
        String driver;
        String vbios;
        String driverVersion;
        String vbiosVersion;
    }

    /** Bytes as Latin-1 characters, trailing NULs removed, JavaScript-trimmed. */
    static String opaqueAscii(byte[] b) {
        if (b == null) return "";
        return AttestCommon.jsTrim(AttestNvidia.stripTrailingNul(new String(b, StandardCharsets.ISO_8859_1)));
    }

    private static final Pattern CHIP_NAME = Pattern.compile("[A-Z][A-Z0-9]{2,11}");

    static RimIds rimIdsForReport(AttestNvidia.SpdmReport rep) {
        Map<Integer, byte[]> o = rep.opaque;
        String driverVersion = opaqueAscii(o.get(AttestNvidia.OPAQUE_DRIVER_VERSION));
        byte[] vb = o.get(AttestNvidia.OPAQUE_VBIOS_VERSION);
        String project = opaqueAscii(o.get(17)).toUpperCase(Locale.ROOT);
        String projectSku = opaqueAscii(o.get(18)).toUpperCase(Locale.ROOT);
        String chipSku = opaqueAscii(o.get(15)).toUpperCase(Locale.ROOT);
        if (driverVersion.isEmpty() || vb == null || project.isEmpty() || projectSku.isEmpty() || chipSku.isEmpty()) return null;
        String chip = "GH100";
        byte[] raw = o.get(AttestNvidia.OPAQUE_CHIP_INFO);
        if (raw != null) {
            chip = opaqueAscii(raw);
            if (!CHIP_NAME.matcher(chip).matches()) return null;
        }
        RimIds ids = new RimIds();
        ids.chip = chip;
        ids.driverVersion = driverVersion;
        ids.vbiosVersion = AttestNvidia.formatVbiosVersion(vb);
        ids.driver = chip.equals("GH100") ? "NV_GPU_DRIVER_GH100_" + driverVersion : "NV_GPU_CC_DRIVER_" + chip + "_" + driverVersion;
        ids.vbios = "NV_GPU_VBIOS_" + project + "_" + projectSku + "_" + chipSku + "_" + ids.vbiosVersion.replace(".", "").toUpperCase(Locale.ROOT);
        return ids;
    }

    /** compareReportToRims (NVIDIA's merge / alternatives / NVDEC0 rules): "" when the report matches. */
    static String compareReportToRims(AttestNvidia.SpdmReport rep, Rim driver, Rim vbios) {
        TreeMap<Long, Golden> merged = new TreeMap<>();
        for (Golden g : driver.golden.values()) if (g.active) merged.put(g.index, g);
        for (Golden g : new TreeMap<>(vbios.golden).values()) {
            if (!g.active) continue;
            if (merged.containsKey(g.index)) return "driver and VBIOS RIMs both have an active measurement at index " + g.index;
            merged.put(g.index, g);
        }
        if (merged.isEmpty()) return "RIMs carry no active golden measurements";
        Map<Long, byte[]> runtime = new HashMap<>();
        for (AttestNvidia.Measurement m : rep.measurements) runtime.put((long) m.index - 1, m.digest);
        if (merged.size() > runtime.size()) return "RIMs list more active measurements than the report carries";
        byte[] nvdec = rep.opaque.get(11);
        boolean nvdecDisabled = nvdec != null && nvdec.length > 0 && (nvdec[0] & 0xff) == NVDEC0_OFF;
        int mismatches = 0;
        for (Map.Entry<Long, Golden> e : merged.entrySet()) {
            long index = e.getKey();
            Golden g = e.getValue();
            if (index + 1 == NVDEC_BLOCK && nvdecDisabled) continue;
            byte[] digest = runtime.get(index);
            if (digest == null || digest.length != g.size || !g.hashes.contains(AttestCommon.toHexLower(digest))) mismatches++;
        }
        if (mismatches > 0) return "runtime measurements differ from the golden RIM values at " + mismatches + " index(es)";
        return "";
    }

    // ------------------------------------------------------------- CRLs

    private static final class Tlv {
        final int tag;
        final int start;
        final int end;

        Tlv(int tag, int start, int end) {
            this.tag = tag;
            this.start = start;
            this.end = end;
        }
    }

    /** A lenient element reader (long forms up to 4 length bytes) bounded by limit; the Go tlvLenient wording. */
    private static Tlv tlvLenient(byte[] b, int off, int limit) {
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
        return new Tlv(tag, p, (int) (p + l));
    }

    private static final Pattern UTC_TIME = Pattern.compile("([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z");
    private static final Pattern GEN_TIME = Pattern.compile("([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z");

    /** Date.UTC (fields roll over; a year 0..99 means 19YY). */
    static long dateUtc(int y, int mo, int d, int h, int mi, int s) {
        if (y >= 0 && y <= 99) y += 1900;
        return LocalDateTime.of(y, 1, 1, 0, 0, 0).plusMonths(mo - 1L).plusDays(d - 1L).plusHours(h).plusMinutes(mi).plusSeconds(s)
            .toInstant(ZoneOffset.UTC).toEpochMilli();
    }

    private static int dig(String s) { return Integer.parseInt(s); }

    private static long crlTime(byte[] b, Tlv t) {
        String s = new String(b, t.start, t.end - t.start, StandardCharsets.ISO_8859_1);
        if (t.tag == 0x17) {
            Matcher m = UTC_TIME.matcher(s);
            if (!m.matches()) throw new AttestException("bad UTCTime");
            int yy = dig(m.group(1));
            return dateUtc(yy >= 50 ? 1900 + yy : 2000 + yy, dig(m.group(2)), dig(m.group(3)), dig(m.group(4)), dig(m.group(5)), dig(m.group(6)));
        }
        if (t.tag == 0x18) {
            Matcher m = GEN_TIME.matcher(s);
            if (!m.matches()) throw new AttestException("bad GeneralizedTime");
            return dateUtc(dig(m.group(1)), dig(m.group(2)), dig(m.group(3)), dig(m.group(4)), dig(m.group(5)), dig(m.group(6)));
        }
        throw new AttestException("not a DER time");
    }

    private static final class ParsedCrl {
        byte[] tbs;
        long thisUpdate;
        long nextUpdate;
        boolean hasNext;
        final Set<String> revoked = new HashSet<>();
        byte[] sigDer;
    }

    private static ParsedCrl parseCrl(byte[] der) {
        Tlv outer = tlvLenient(der, 0, der.length);
        if (outer.tag != 0x30 || outer.end != der.length) throw new AttestException("CRL: bad outer SEQUENCE");
        Tlv tbsT = tlvLenient(der, outer.start, outer.end);
        if (tbsT.tag != 0x30) throw new AttestException("CRL: bad TBSCertList");
        ParsedCrl crl = new ParsedCrl();
        crl.tbs = Arrays.copyOfRange(der, outer.start, tbsT.end);
        Tlv algT = tlvLenient(der, tbsT.end, outer.end);
        Tlv sigT = tlvLenient(der, algT.end, outer.end);
        if (sigT.tag != 0x03 || sigT.end != outer.end) throw new AttestException("CRL: bad signature");
        crl.sigDer = sigT.start + 1 <= sigT.end ? Arrays.copyOfRange(der, sigT.start + 1, sigT.end) : new byte[0];
        int p = tbsT.start;
        Tlv t = tlvLenient(der, p, tbsT.end);
        if (t.tag == 0x02) {
            p = t.end;
            t = tlvLenient(der, p, tbsT.end);
        }
        p = t.end; // signature AlgorithmIdentifier
        Tlv iss = tlvLenient(der, p, tbsT.end);
        if (iss.tag != 0x30) throw new AttestException("CRL: bad issuer");
        Tlv tu = tlvLenient(der, iss.end, tbsT.end);
        crl.thisUpdate = crlTime(der, tu);
        int q = tu.end;
        if (q < tbsT.end) {
            Tlv n = tlvLenient(der, q, tbsT.end);
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
                        Tlv ent = tlvLenient(der, e, n.end);
                        Tlv ser = tlvLenient(der, ent.start, ent.end);
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
    private static boolean crlSigOk(byte[] tbs, byte[] sig, CertKey k) {
        try {
            String alg;
            if (k.pub instanceof ECPublicKey) alg = "SHA256withECDSA";
            else if (k.pub instanceof RSAPublicKey) alg = "SHA256withRSA";
            else return false;
            Signature s = Signature.getInstance(alg);
            s.initVerify(k.pub);
            s.update(tbs);
            return s.verify(sig);
        } catch (java.security.GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** The revoked serials of a verified CRL, or the failure reason. */
    static final class CrlResult {
        final Set<String> revoked;
        final String reason;

        CrlResult(Set<String> revoked, String reason) {
            this.revoked = revoked;
            this.reason = reason;
        }
    }

    /** verifyCRL: a DER CRL under the issuer key at nowMs. Revoked serials are lowercase hex without leading zeros. */
    static CrlResult verifyCrl(byte[] der, CertKey issuer, long nowMs) {
        ParsedCrl crl;
        try {
            crl = parseCrl(der);
        } catch (AttestException | java.time.DateTimeException e) {
            return new CrlResult(null, "CRL parse failed: " + AttestCommon.errMsg(e));
        }
        if (!crlSigOk(crl.tbs, crl.sigDer, issuer)) return new CrlResult(null, "CRL signature does not verify under the issuer");
        if (nowMs < crl.thisUpdate) return new CrlResult(null, "CRL thisUpdate is in the future");
        if (nowMs > crl.nextUpdate) return new CrlResult(null, "CRL is stale (nextUpdate passed)");
        return new CrlResult(crl.revoked, "");
    }

    /**
     * checkNvidiaChainRevocation: every CRL must verify under one chain certificate and be fresh, no chain certificate may be
     * listed by its issuer's CRL, and each required issuer must have a verified CRL. "" when it holds.
     */
    static String checkChainRevocation(List<AttCert> chain, List<byte[]> crls, long nowMs, List<String> requireIssuers) {
        if (crls.isEmpty()) return "no CRLs supplied";
        Set<Integer> covered = new HashSet<>();
        for (int ci = 0; ci < crls.size(); ci++) {
            int issuerIdx = -1;
            Set<String> revoked = null;
            String lastReason = "no chain certificate verifies it";
            for (int i = 0; i < chain.size(); i++) {
                CertKey k;
                try {
                    k = AttestCert.keyOfCert(chain.get(i));
                } catch (AttestException e) {
                    continue;
                }
                CrlResult r = verifyCrl(crls.get(ci), k, nowMs);
                if (r.reason.isEmpty()) {
                    issuerIdx = i;
                    revoked = r.revoked;
                    break;
                }
                if (lastReason.equals("no chain certificate verifies it") || lastReason.contains("signature does not verify")) lastReason = r.reason;
            }
            if (issuerIdx < 0 || revoked == null) return "CRL #" + ci + " rejected: " + lastReason;
            covered.add(issuerIdx);
            for (int i = 0; i < chain.size() - 1; i++) {
                if (i + 1 == issuerIdx && revoked.contains(chain.get(i).serialHex())) {
                    return "chain certificate '" + AttestNvidia.subjectLine(chain.get(i)) + "' is revoked";
                }
            }
        }
        for (String need : requireIssuers) {
            boolean found = false;
            for (int i : covered) if (AttestCommon.nameText(chain.get(i).rawSubject).contains(need)) found = true;
            if (!found) return "no verified CRL issued by a certificate matching '" + need + "'";
        }
        return "";
    }

    // ------------------------------------------------------------- firmware policy

    private static final Pattern DEC10_VERSION = Pattern.compile("[0-9]+(\\.[0-9]+)*");
    private static final Pattern HEX16_VERSION = Pattern.compile("[0-9a-fA-F]{1,4}(\\.[0-9a-fA-F]{1,4})*");

    /** The numeric components of a version, or null when it is malformed. */
    static double[] parseVersion(String v, int radix) {
        if (!(radix == 16 ? HEX16_VERSION : DEC10_VERSION).matcher(v).matches()) return null;
        String[] parts = v.split("\\.", -1);
        double[] out = new double[parts.length];
        for (int i = 0; i < parts.length; i++) out[i] = new BigInteger(parts[i], radix).doubleValue();
        return out;
    }

    static int cmpVersion(double[] a, double[] b) {
        int n = Math.max(a.length, b.length);
        for (int i = 0; i < n; i++) {
            double x = i < a.length ? a[i] : 0;
            double y = i < b.length ? b[i] : 0;
            if (x != y) return x < y ? -1 : 1;
        }
        return 0;
    }

    /** The string members of a JSON array (empty when v is not an array). */
    static List<String> anyStrings(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof List) for (Object x : (List<?>) v) if (x instanceof String) out.add((String) x);
        return out;
    }

    static final class FirmwarePolicy {
        double[] minD;
        double[] minV;
        String minDText = "";
        String minVText = "";
        final List<double[]> denyD = new ArrayList<>();
        final List<double[]> denyV = new ArrayList<>();

        private static double[] need(String v, int radix, String what) {
            double[] p = parseVersion(v, radix);
            if (p == null) throw new AttestException("nvidiaCollateralHook: malformed " + what + " '" + v + "'");
            return p;
        }

        static FirmwarePolicy compile(Map<String, Object> fw) {
            FirmwarePolicy p = new FirmwarePolicy();
            Object s = fw.get("minDriverVersion");
            if (s instanceof String && !((String) s).isEmpty()) {
                p.minD = need((String) s, 10, "minDriverVersion");
                p.minDText = (String) s;
            }
            s = fw.get("minVbiosVersion");
            if (s instanceof String && !((String) s).isEmpty()) {
                p.minV = need((String) s, 16, "minVbiosVersion");
                p.minVText = (String) s;
            }
            for (String x : anyStrings(fw.get("denyDriverVersions"))) p.denyD.add(need(x, 10, "denyDriverVersions entry"));
            for (String x : anyStrings(fw.get("denyVbiosVersions"))) p.denyV.add(need(x, 16, "denyVbiosVersions entry"));
            return p;
        }

        String check(RimIds ids) {
            double[] d = parseVersion(ids.driverVersion, 10);
            double[] v = parseVersion(ids.vbiosVersion, 16);
            if (d == null) return "driver version '" + ids.driverVersion + "' in the GPU report is not parseable";
            if (v == null) return "VBIOS version '" + ids.vbiosVersion + "' in the GPU report is not parseable";
            if (minD != null && cmpVersion(d, minD) < 0) return "driver " + ids.driverVersion + " is below the minimum " + minDText;
            if (minV != null && cmpVersion(v, minV) < 0) return "VBIOS " + ids.vbiosVersion + " is below the minimum " + minVText;
            for (double[] x : denyD) if (cmpVersion(d, x) == 0) return "driver " + ids.driverVersion + " is on the deny list";
            for (double[] x : denyV) if (cmpVersion(v, x) == 0) return "VBIOS " + ids.vbiosVersion + " is on the deny list";
            return "";
        }
    }

    // ------------------------------------------------------------- the collateral hook

    /** The collateral one evidence object carries. */
    static final class Bundle {
        String driverRim = "";
        String vbiosRim = "";
        final List<byte[]> crls = new ArrayList<>();
        final List<byte[]> ocsp = new ArrayList<>();
    }

    /** The post-verification collateral check of the NVIDIA verifier. Its bundle is the collateral the evidence carries. */
    static final class Hook {
        List<String> rimPins;
        String revocation;
        boolean requireCrls;
        List<String> requireIssuers;
        FirmwarePolicy firmware;
        Bundle bundle;

        static Hook create(Map<String, Object> col) {
            Hook h = new Hook();
            h.requireCrls = !Boolean.FALSE.equals(col.get("requireCrls"));
            List<String> pins = AttestCommon.asStrList(col.get("rimRootSpkiSha256"));
            if (pins == null || pins.isEmpty()) throw new AttestException("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root");
            h.rimPins = pins;
            Map<String, Object> fw = AttestCommon.asRec(col.get("firmware"));
            if (fw != null) h.firmware = FirmwarePolicy.compile(fw);
            if (col.get("revocation") instanceof String) h.revocation = (String) col.get("revocation");
            h.requireIssuers = anyStrings(col.get("requireCrlIssuers"));
            return h;
        }

        /** The hook bound to the collateral of one evidence object (null: none supplied). */
        Hook withBundle(Map<String, Object> c) {
            Hook cp = new Hook();
            cp.rimPins = rimPins;
            cp.revocation = revocation;
            cp.requireCrls = requireCrls;
            cp.requireIssuers = requireIssuers;
            cp.firmware = firmware;
            if (c == null) return cp;
            Bundle b = new Bundle();
            if (c.get("driverRimXml") instanceof String) b.driverRim = (String) c.get("driverRimXml");
            if (c.get("vbiosRimXml") instanceof String) b.vbiosRim = (String) c.get("vbiosRimXml");
            for (String s : anyStrings(c.get("crls"))) b.crls.add(AttestCommon.nodeB64(s));
            for (String s : anyStrings(c.get("ocsp"))) b.ocsp.add(AttestCommon.nodeB64(s));
            cp.bundle = b;
            return cp;
        }

        /** The hook proper: the failure reason, or "" when the collateral holds. */
        String run(AttestNvidia.SpdmReport rep, List<AttCert> chain, long nowMs) {
            RimIds ids = rimIdsForReport(rep);
            if (ids == null) return "GPU report does not carry the opaque fields needed to name its RIMs";
            String subject = AttestCommon.nameText(chain.get(0).rawSubject);
            Pattern chipRe = Pattern.compile("(^|[^A-Za-z0-9])" + Pattern.quote(ids.chip) + "([^A-Za-z0-9]|$)");
            if (!chipRe.matcher(subject).find()) {
                return "device leaf subject '" + subject.replace("\n", ", ") + "' is not a " + ids.chip + " device certificate (chip family mismatch)";
            }
            if (firmware != null) {
                String why = firmware.check(ids);
                if (!why.isEmpty()) return "firmware policy: " + why;
            }
            if (bundle == null) return "no RIM collateral supplied for this report";
            RimResult d = verifyRim(bundle.driverRim, rimPins, nowMs);
            RimResult v = verifyRim(bundle.vbiosRim, rimPins, nowMs);
            if (d.rim == null) return "driver RIM: " + d.reason;
            if (v.rim == null) return "VBIOS RIM: " + v.reason;
            if (!d.rim.product.equals(ids.chip)) {
                return "driver RIM product '" + d.rim.product + "' does not match the GPU chip '" + ids.chip + "' (wrong-family manifest)";
            }
            if (!v.rim.product.equals(ids.chip)) {
                return "VBIOS RIM product '" + v.rim.product + "' does not match the GPU chip '" + ids.chip + "' (wrong-family manifest)";
            }
            if (!d.rim.version.equals(ids.driverVersion)) {
                return "driver RIM version '" + d.rim.version + "' does not match the report's driver '" + ids.driverVersion + "'";
            }
            if (!v.rim.version.replace(".", "").toUpperCase(Locale.ROOT).equals(ids.vbiosVersion.replace(".", "").toUpperCase(Locale.ROOT))) {
                return "VBIOS RIM version '" + v.rim.version + "' does not match the report's VBIOS '" + ids.vbiosVersion + "'";
            }
            String why = compareReportToRims(rep, d.rim, v.rim);
            if (!why.isEmpty()) return why;
            String mode = revocation != null ? revocation : requireCrls ? "crl" : "";
            if (!bundle.crls.isEmpty() || mode.equals("crl") || mode.equals("both")) {
                why = checkChainRevocation(chain, bundle.crls, nowMs, requireIssuers);
                if (!why.isEmpty()) return "revocation: " + why;
            }
            if (!bundle.ocsp.isEmpty() || mode.equals("ocsp") || mode.equals("both")) {
                why = AttestNvidiaOcsp.checkChainOcsp(chain, bundle.ocsp, nowMs);
                if (!why.isEmpty()) return "revocation (OCSP): " + why;
            }
            return "";
        }
    }
}
