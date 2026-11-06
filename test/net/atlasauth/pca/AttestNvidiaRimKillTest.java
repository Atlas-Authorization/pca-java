package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

/**
 * Exact-outcome tests of the NVIDIA RIM collateral (AttestNvidiaRim): a RIM document signed at run time under a pinned P-384
 * chain plus a tamper matrix over every structural, cryptographic and measurement check; the CRL reader (DER lengths, both
 * time forms pinned to the millisecond through the freshness window, revoked serials, signature algorithms); chain
 * revocation; the firmware policy; and the collateral hook end to end.
 */
public class AttestNvidiaRimKillTest {
    static final long NOW = AttestNvidiaTest.NOW;
    static final AttestNvidiaTest.Gpu G = new AttestNvidiaTest.Gpu();
    static final List<String> PINS = Collections.singletonList(G.pin());

    static final String DS = AttestNvidiaRim.NS_DSIG;
    static final String SWID = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd";

    static final String CM = "<ds:CanonicalizationMethod Algorithm=\"" + AttestNvidiaRim.ALG_C14N11 + "\"/>";
    static final String SM = "<ds:SignatureMethod Algorithm=\"" + AttestNvidiaRim.ALG_ECDSA384 + "\"/>";
    static final String T1 = "<ds:Transform Algorithm=\"" + AttestNvidiaRim.ALG_ENVELOPED + "\"/>";
    static final String T2 = "<ds:Transform Algorithm=\"" + AttestNvidiaRim.ALG_C14N11 + "\"/>";
    static final String TS = "<ds:Transforms>" + T1 + T2 + "</ds:Transforms>";
    static final String DM = "<ds:DigestMethod Algorithm=\"" + AttestNvidiaRim.ALG_SHA384 + "\"/>";
    static final String DV = "<ds:DigestValue>\n @DIG@ \n</ds:DigestValue>";
    static final String REF = "<ds:Reference URI=\"\">" + TS + DM + DV + "</ds:Reference>";
    static final String SI = "<ds:SignedInfo>" + CM + SM + REF + "</ds:SignedInfo>";
    static final String SV = "<ds:SignatureValue>\n@SIG@\n</ds:SignatureValue>";
    static final String X509 = "<ds:X509Certificate>" + certText(G.leafDer) + "</ds:X509Certificate><ds:X509Certificate>" + certText(G.rootDer) + "</ds:X509Certificate>";
    static final String KI = "<ds:KeyInfo><ds:X509Data>" + X509 + "</ds:X509Data></ds:KeyInfo>";
    static final String SIG = "<ds:Signature>" + SI + SV + KI + "</ds:Signature>";

    static final String H1 = AttestCommon.toHexLower(AttestNvidiaTest.M1);
    static final String H2 = AttestCommon.toHexLower(AttestNvidiaTest.M2);

    /** A certificate's base64 with a line break and a no-break space inside (JavaScript whitespace the PEM reader does not skip). */
    static String certText(byte[] der) {
        String b = Base64.getEncoder().encodeToString(der);
        return "\n" + b.substring(0, 10) + "\u00a0" + b.substring(10) + "\n";
    }

    static String res(String attrs) { return "<Resource type=\"Measurement\" " + attrs + "/>"; }

    static String m(long index, String hex) {
        return res("index=\"" + index + "\" active=\"true\" alternatives=\"1\" size=\"" + hex.length() / 2 + "\" Hash0=\"" + hex + "\"");
    }

    static String doc(String product, String version, String payload) {
        return "<SoftwareIdentity xmlns=\"" + SWID + "\" xmlns:ds=\"" + DS + "\" name=\"rim\">\n<Meta product=\"" + product
            + "\" colloquialVersion=\"" + version + "\"/>\n<Payload>" + payload + "</Payload>\n" + SIG + "\n</SoftwareIdentity>";
    }

    static final String BASE = doc("GH100", "535.86", m(0, H1));

    static String swap(String s, String a, String b) {
        assertTrue(s.contains(a), "template lacks " + a);
        return s.replace(a, b);
    }

    /** Fills @DIG@ (the enveloped digest) and @SIG@ (ECDSA P-384 over the canonical SignedInfo) with the signer key. */
    static String sign(KeyPair signer, String t) {
        AttestXml.Doc d0 = AttestXml.parseXml(t);
        AttestXml.Node sig0 = d0.root.elementChildrenNs(DS, "Signature").get(0);
        String dig = Base64.getEncoder().encodeToString(AttestCommon.sha384Sum(
            AttestXml.canonicalize(d0.root, new HashMap<String, String>(), sig0).getBytes(StandardCharsets.UTF_8)));
        String t2 = t.replace("@DIG@", dig);
        AttestXml.Node si = AttestXml.parseXml(t2).root.elementChildrenNs(DS, "Signature").get(0).elementChildrenNs(DS, "SignedInfo").get(0);
        byte[] c = AttestXml.canonicalize(si, si.parent.scope(), null).getBytes(StandardCharsets.UTF_8);
        try {
            Signature s = Signature.getInstance("SHA384withECDSAinP1363Format");
            s.initSign(signer.getPrivate());
            s.update(c);
            return t2.replace("@SIG@", Base64.getEncoder().encodeToString(s.sign()));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String sign(String t) { return sign(G.leaf, t); }

    static String reason(String xml) { return AttestNvidiaRim.verifyRim(xml, PINS, NOW).reason; }

    /** product|version|index:active:alternatives:size:hashes;... in index order. */
    static String describe(AttestNvidiaRim.Rim r) {
        StringBuilder sb = new StringBuilder(r.product + "|" + r.version);
        for (AttestNvidiaRim.Golden g : new TreeMap<>(r.golden).values()) {
            sb.append('|').append(g.index).append(':').append(g.active).append(':').append(g.alternatives).append(':').append(g.size).append(':').append(g.hashes);
        }
        return sb.toString();
    }

    static String valid(String xml) {
        AttestNvidiaRim.RimResult r = AttestNvidiaRim.verifyRim(xml, PINS, NOW);
        assertEquals("", r.reason);
        return describe(r.rim);
    }

    // ------------------------------------------------------------- helpers

    @Test
    void textHelpers() {
        assertEquals("abc", AttestNvidiaRim.stripJsSpace(" a\u00a0b\n\u2028c\t"));
        assertEquals("", AttestNvidiaRim.stripJsSpace(" \n"));
        String a64 = "A".repeat(64);
        assertEquals("-----BEGIN CERTIFICATE-----\n" + a64 + "\n-----END CERTIFICATE-----", AttestNvidiaRim.pemOfDerB64(a64 + " "));
        assertEquals("-----BEGIN CERTIFICATE-----\n" + a64 + "\nBB\n-----END CERTIFICATE-----", AttestNvidiaRim.pemOfDerB64(a64 + "\u00a0B B"));
        assertEquals("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----", AttestNvidiaRim.pemOfDerB64(""));
        assertEquals(Arrays.asList("a", "b"), AttestNvidiaRim.anyStrings(Arrays.asList("a", 1.0, null, "b")));
        assertEquals(new ArrayList<String>(), AttestNvidiaRim.anyStrings("a"));
    }

    // ------------------------------------------------------------- the RIM document

    @Test
    void validRim() {
        assertEquals("GH100|535.86|0:true:1:48:[" + H1 + "]", valid(sign(BASE)));
        // Hash attributes in numeric order (not insertion, not lexical), lower-cased; active is case-insensitive
        String odd = res("index=\"3\" active=\"TRUE\" alternatives=\"3\" size=\"1\" Hash10=\"0A\" Hash2=\"02\" Hash1=\"01\"")
            + res("index=\"0\" alternatives=\"1\" size=\"1\" Hash0=\"ab\"");
        assertEquals("GB100|9|0:false:1:1:[ab]|3:true:3:1:[01, 02, 0a]", valid(sign(doc("GB100", "9", odd))));
        // only Resource children of type Measurement are read
        String skipped = "<Other type=\"Measurement\" index=\"x\"/>" + res("index=\"x\"").replace("Measurement", "Other") + m(0, H1);
        assertEquals("GH100|535.86|0:true:1:48:[" + H1 + "]", valid(sign(doc("GH100", "535.86", skipped))));
        // the first Meta and the first Payload are used
        String twoMeta = swap(BASE, "<Payload>", "<Meta product=\"GB100\" colloquialVersion=\"1\"/><Payload>");
        assertEquals("GH100|535.86|0:true:1:48:[" + H1 + "]", valid(sign(twoMeta)));
        String twoPayload = swap(BASE, "</Payload>", "</Payload><Payload>" + m(5, H2) + "</Payload>");
        assertEquals("GH100|535.86|0:true:1:48:[" + H1 + "]", valid(sign(twoPayload)));
        // Transform elements directly under the Reference are read there
        assertEquals("GH100|535.86|0:true:1:48:[" + H1 + "]", valid(sign(swap(BASE, TS, T1 + T2))));
        // a Reference without a URI attribute is the whole document
        assertEquals("GH100|535.86|0:true:1:48:[" + H1 + "]", valid(sign(swap(BASE, "<ds:Reference URI=\"\">", "<ds:Reference>"))));
    }

    @Test
    void sizeAndPins() {
        assertEquals("RIM: empty or oversized document", reason(""));
        String big = "<a/>" + " ".repeat(4_000_000 - 4);
        assertEquals("RIM: root element is not SoftwareIdentity", reason(big));
        assertEquals("RIM: empty or oversized document", reason(big + " "));
        assertEquals("RIM: no pinned RIM root configured", AttestNvidiaRim.verifyRim(sign(BASE), new ArrayList<String>(), NOW).reason);
        assertEquals("RIM signer chain: chain root is not a pinned NVIDIA root",
            AttestNvidiaRim.verifyRim(sign(BASE), Collections.singletonList("00".repeat(32)), NOW).reason);
    }

    @Test
    void structuralTamperMatrix() {
        String b96 = "RIM: SignatureValue is not a 96-byte P-384 signature";
        String parseMsg;
        try {
            AttestXml.parseXml("<a>");
            parseMsg = "no error";
        } catch (AttestException e) {
            parseMsg = e.getMessage();
        }
        String[][] rows = {
            {BASE, b96}, // unsigned: every structural check passes, the signature length is the first refusal
            {"<a>", "RIM: verification error (fail closed): " + parseMsg},
            {"<!--c-->" + BASE, "RIM: XML comments are not permitted"},
            {swap(swap(BASE, "<SoftwareIdentity ", "<Swid "), "</SoftwareIdentity>", "</Swid>"), "RIM: root element is not SoftwareIdentity"},
            {swap(BASE, SIG, ""), "RIM: expected exactly one Signature element"},
            {swap(BASE, SIG, SIG + SIG), "RIM: expected exactly one Signature element"},
            {swap(swap(BASE, SIG, ""), "<Payload>", "<Payload>" + SIG), "RIM: the Signature must be a direct child of the root"},
            {swap(BASE, SI, ""), "RIM: expected exactly one SignedInfo"},
            {swap(BASE, SI, SI + SI), "RIM: expected exactly one SignedInfo"},
            {swap(BASE, CM, ""), "RIM: CanonicalizationMethod must be C14N 1.1"},
            {swap(BASE, CM, "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"), "RIM: CanonicalizationMethod must be C14N 1.1"},
            {swap(BASE, SM, ""), "RIM: SignatureMethod must be ECDSA-SHA384"},
            {swap(BASE, SM, "<ds:SignatureMethod Algorithm=\"" + AttestNvidiaRim.ALG_SHA384 + "\"/>"), "RIM: SignatureMethod must be ECDSA-SHA384"},
            {swap(BASE, REF, ""), "RIM: expected exactly one Reference"},
            {swap(BASE, REF, REF + REF), "RIM: expected exactly one Reference"},
            {swap(BASE, "<ds:Reference URI=\"\">", "<ds:Reference URI=\"#x\">"), "RIM: Reference URI must be \"\" (the whole document)"},
            {swap(BASE, TS, "<ds:Transforms></ds:Transforms>" + T1 + T2), "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"},
            {swap(BASE, TS, "<ds:Transforms>" + T1 + "</ds:Transforms>"), "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"},
            {swap(BASE, TS, "<ds:Transforms>" + T1 + T2 + T2 + "</ds:Transforms>"), "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"},
            {swap(BASE, TS, "<ds:Transforms>" + T2 + T1 + "</ds:Transforms>"), "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"},
            {swap(BASE, TS, "<ds:Transforms>" + T2 + T2 + "</ds:Transforms>"), "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"},
            {swap(BASE, TS, "<ds:Transforms>" + T1 + T1 + "</ds:Transforms>"), "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"},
            {swap(BASE, DM, ""), "RIM: DigestMethod must be SHA-384"},
            {swap(BASE, DM, "<ds:DigestMethod Algorithm=\"" + AttestNvidiaRim.ALG_C14N11 + "\"/>"), "RIM: DigestMethod must be SHA-384"},
            {swap(BASE, DV, ""), "RIM: missing DigestValue / SignatureValue"},
            {swap(BASE, DV, "<ds:DigestValue>\n \u00a0 </ds:DigestValue>"), "RIM: missing DigestValue / SignatureValue"},
            {swap(BASE, SV, ""), "RIM: missing DigestValue / SignatureValue"},
            {swap(BASE, SV, "<ds:SignatureValue>\n \u00a0 </ds:SignatureValue>"), "RIM: missing DigestValue / SignatureValue"},
            {swap(BASE, KI, ""), "RIM: no signer certificates in KeyInfo"},
            {swap(BASE, KI, "<ds:KeyInfo></ds:KeyInfo>"), "RIM: no signer certificates in KeyInfo"},
            {swap(BASE, KI, "<ds:KeyInfo><ds:X509Data></ds:X509Data></ds:KeyInfo>"), "RIM: no signer certificates in KeyInfo"},
        };
        for (String[] r : rows) assertEquals(r[1], reason(r[0]), r[0]);
    }

    @Test
    void cryptographicTampers() {
        String good = sign(BASE);
        KeyPair stranger = ecKey("secp384r1");
        assertEquals("RIM: SignedInfo signature does not verify under the signer certificate", reason(sign(stranger, BASE)));
        assertEquals("RIM: document digest does not match the signed DigestValue", reason(swap(good, "colloquialVersion=\"535.86\"", "colloquialVersion=\"535.87\"")));
        int a = good.indexOf("<ds:SignatureValue>");
        int z = good.indexOf("</ds:SignatureValue>");
        String short95 = good.substring(0, a) + "<ds:SignatureValue>" + Base64.getEncoder().encodeToString(new byte[95]) + good.substring(z);
        assertEquals("RIM: SignatureValue is not a 96-byte P-384 signature", reason(short95));
        String zero96 = good.substring(0, a) + "<ds:SignatureValue>" + Base64.getEncoder().encodeToString(new byte[96]) + good.substring(z);
        assertEquals("RIM: SignedInfo signature does not verify under the signer certificate", reason(zero96));
    }

    @Test
    void measurementTamperMatrix() {
        String malformed = "RIM: malformed Measurement resource";
        String[][] rows = {
            {swap(BASE, "<Meta product=\"GH100\" colloquialVersion=\"535.86\"/>", ""), "RIM: missing Meta / Payload"},
            {swap(BASE, "<Payload>" + m(0, H1) + "</Payload>", ""), "RIM: missing Meta / Payload"},
            {doc("GH100", "1", ""), "RIM: no measurements"},
            {doc("GH100", "1", res("index=\"1.5\" alternatives=\"1\" size=\"1\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"-1\" alternatives=\"1\" size=\"1\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"x\" alternatives=\"1\" size=\"1\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"1\" alternatives=\"0\" size=\"1\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"1\" alternatives=\"1.5\" size=\"1\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"1\" alternatives=\"Infinity\" size=\"1\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"1\" alternatives=\"1\" size=\"0\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"1\" alternatives=\"1\" size=\"2.5\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"1\" alternatives=\"1\" size=\"-1\" Hash0=\"ab\"")), malformed},
            {doc("GH100", "1", res("index=\"7\" alternatives=\"2\" size=\"1\" Hash0=\"ab\"")), "RIM: Measurement 7 hash list is inconsistent with alternatives/size"},
            {doc("GH100", "1", res("index=\"7\" alternatives=\"1\" size=\"1\" Hash0=\"ab\" Hash1=\"cd\"")), "RIM: Measurement 7 hash list is inconsistent with alternatives/size"},
            {doc("GH100", "1", res("index=\"7\" alternatives=\"1\" size=\"1\" Hash0=\"zz\"")), "RIM: Measurement 7 hash list is inconsistent with alternatives/size"},
            {doc("GH100", "1", res("index=\"7\" alternatives=\"1\" size=\"1\" Hash0=\"abcd\"")), "RIM: Measurement 7 hash list is inconsistent with alternatives/size"},
            {doc("GH100", "1", res("index=\"7\" alternatives=\"1\" size=\"2\" Hash0=\"ab\"")), "RIM: Measurement 7 hash list is inconsistent with alternatives/size"},
            {doc("GH100", "1", m(2, "ab") + m(2, "cd")), "RIM: duplicate Measurement index 2"},
        };
        for (String[] r : rows) assertEquals(r[1], reason(sign(r[0])), r[0]);
    }

    // ------------------------------------------------------------- RIM naming and the golden comparison

    static AttestNvidia.SpdmReport report(List<byte[]> blocks, byte[] opaque) {
        return AttestNvidia.parseSpdmEvidence(cat(AttestNvidiaTest.transcript(new byte[32], blocks, opaque), new byte[96]));
    }

    static AttestNvidia.SpdmReport fullReport() {
        return report(Arrays.asList(AttestNvidiaTest.block(1, AttestNvidiaTest.M1), AttestNvidiaTest.block(2, AttestNvidiaTest.M2)), AttestNvidiaTest.opaqueAll("535.86"));
    }

    @Test
    void rimIdsNeedEveryField() {
        AttestNvidia.SpdmReport rep = fullReport();
        rep.opaque.put(18, "ab12".getBytes(StandardCharsets.ISO_8859_1));
        AttestNvidiaRim.RimIds ids = AttestNvidiaRim.rimIdsForReport(rep);
        assertEquals("NV_GPU_VBIOS_PG520_AB12_G520_96009F0004", ids.vbios);
        assertEquals("96.00.9f.00.04", ids.vbiosVersion);
        assertEquals("535.86", ids.driverVersion);
        for (int key : new int[] {6, 15, 17, 18}) {
            AttestNvidia.SpdmReport r = fullReport();
            r.opaque.remove(key);
            assertNull(AttestNvidiaRim.rimIdsForReport(r), "opaque " + key);
        }
        for (int key : new int[] {15, 17, 18}) {
            AttestNvidia.SpdmReport r = fullReport();
            r.opaque.put(key, " \0".getBytes(StandardCharsets.ISO_8859_1));
            assertNull(AttestNvidiaRim.rimIdsForReport(r), "blank opaque " + key);
        }
    }

    static AttestNvidiaRim.Rim rimOf(AttestNvidiaRim.Golden... gs) {
        Map<Long, AttestNvidiaRim.Golden> m = new HashMap<>();
        for (AttestNvidiaRim.Golden g : gs) m.put(g.index, g);
        return new AttestNvidiaRim.Rim("GH100", "1", m);
    }

    @Test
    void goldenEdges() {
        AttestNvidia.SpdmReport one = report(Arrays.asList(AttestNvidiaTest.block(1, AttestNvidiaTest.M1)), new byte[0]);
        AttestNvidiaRim.Rim none = rimOf();
        // as many active goldens as report blocks
        assertEquals("", AttestNvidiaRim.compareReportToRims(one, rimOf(new AttestNvidiaRim.Golden(0, true, 1, 48, Arrays.asList(H1))), none));
        // the digest length must equal the golden size even when its hex is listed
        assertEquals("runtime measurements differ from the golden RIM values at 1 index(es)",
            AttestNvidiaRim.compareReportToRims(one, rimOf(new AttestNvidiaRim.Golden(0, true, 1, 32, Arrays.asList(H1))), none));
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 1; i <= 35; i++) blocks.add(AttestNvidiaTest.block(i, AttestNvidiaTest.filled(48, i)));
        AttestNvidiaRim.Rim bad34 = rimOf(new AttestNvidiaRim.Golden(34, true, 1, 48, Arrays.asList("ff")));
        // no NVDEC0 opaque field, or an empty one: block 35 is compared
        AttestNvidia.SpdmReport noNvdec = report(blocks, new byte[0]);
        assertEquals("runtime measurements differ from the golden RIM values at 1 index(es)", AttestNvidiaRim.compareReportToRims(noNvdec, bad34, none));
        AttestNvidia.SpdmReport emptyNvdec = report(blocks, AttestNvidiaTest.tlvOpaque(11, new byte[0]));
        assertEquals("runtime measurements differ from the golden RIM values at 1 index(es)", AttestNvidiaRim.compareReportToRims(emptyNvdec, bad34, none));
        AttestNvidia.SpdmReport off = report(blocks, AttestNvidiaTest.tlvOpaque(11, new byte[] {0x55, 0x00}));
        assertEquals("", AttestNvidiaRim.compareReportToRims(off, bad34, none));
    }

    // ------------------------------------------------------------- CRLs

    static final AttCert LEAF = AttestCert.parseCertDer(G.leafDer);
    static final AttCert ROOT = AttestCert.parseCertDer(G.rootDer);
    static final List<AttCert> CHAIN = Arrays.asList(LEAF, ROOT);
    static final CertKey ROOT_KEY = AttestCert.keyOfCert(ROOT);

    static byte[] utc(String s) { return withTag(0x17, s.getBytes(StandardCharsets.US_ASCII)); }

    static byte[] gen(String s) { return withTag(0x18, s.getBytes(StandardCharsets.US_ASCII)); }

    static final byte[] THIS = gen("20260315102030Z");
    static final byte[] NEXT = gen("20270416112131Z");
    static final long THIS_MS = 1773570030000L;
    static final long NEXT_MS = 1807874491000L;

    static byte[] revokedList(byte[]... serials) {
        List<byte[]> entries = new ArrayList<>();
        for (byte[] s : serials) entries.add(seq(withTag(0x02, s), utc("250101000000Z")));
        return seq(cat(entries.toArray(new byte[0][])));
    }

    static byte[] tbs(byte[] version, byte[] thisU, byte[] nextU, byte[] rest) {
        return seq(version, SIG_ALG_ECDSA_SHA256, name("NV Root"), thisU, nextU, rest);
    }

    static byte[] sig(KeyPair k, String alg, byte[] tbs) {
        try {
            Signature s = Signature.getInstance(alg);
            s.initSign(k.getPrivate());
            s.update(tbs);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] crl(KeyPair k, byte[] tbs) { return seq(tbs, SIG_ALG_ECDSA_SHA256, bits((byte) 0, sig(k, "SHA256withECDSA", tbs))); }

    static byte[] crlOf(KeyPair k, byte[]... revoked) { return crl(k, tbs(integer(1), THIS, NEXT, revoked.length == 0 ? new byte[0] : revokedList(revoked))); }

    static String crlReason(byte[] der) { return AttestNvidiaRim.verifyCrl(der, ROOT_KEY, NOW).reason; }

    static void window(byte[] thisU, byte[] nextU, long t, long n) {
        byte[] c = crl(G.root, tbs(integer(1), thisU, nextU, new byte[0]));
        assertEquals("CRL thisUpdate is in the future", AttestNvidiaRim.verifyCrl(c, ROOT_KEY, t - 1).reason);
        assertEquals("", AttestNvidiaRim.verifyCrl(c, ROOT_KEY, t).reason);
        assertEquals("", AttestNvidiaRim.verifyCrl(c, ROOT_KEY, n).reason);
        assertEquals("CRL is stale (nextUpdate passed)", AttestNvidiaRim.verifyCrl(c, ROOT_KEY, n + 1).reason);
    }

    @Test
    void crlTimesToTheMillisecond() {
        window(THIS, NEXT, THIS_MS, NEXT_MS);
        // UTCTime: 50 is 1950, 49 is 2049
        window(utc("500203040506Z"), utc("490708091011Z"), -628286094000L, 2509348211000L);
        window(utc("500203040506Z"), NEXT, -628286094000L, NEXT_MS);
        // Date.UTC: years 0..99 are 19YY, fields roll over
        assertEquals(915148800000L, AttestNvidiaRim.dateUtc(99, 1, 1, 0, 0, 0));
        assertEquals(-2208988800000L, AttestNvidiaRim.dateUtc(0, 1, 1, 0, 0, 0));
        assertEquals(-59011459200000L, AttestNvidiaRim.dateUtc(100, 1, 1, 0, 0, 0));
        assertEquals(1773570030000L, AttestNvidiaRim.dateUtc(2026, 3, 15, 10, 20, 30));
        assertEquals(946684799000L, AttestNvidiaRim.dateUtc(1999, 12, 31, 23, 59, 59));
    }

    @Test
    void crlStructureMatrix() {
        assertEquals("", crlReason(crlOf(G.root)));
        assertEquals("", crlReason(crl(G.root, tbs(new byte[0], THIS, NEXT, new byte[0])))); // v1: no version
        assertEquals("", crlReason(crl(G.root, tbs(integer(1), THIS, NEXT, withTag(0xa0, seq()))))); // extensions are skipped
        AttestNvidiaRim.CrlResult r = AttestNvidiaRim.verifyCrl(crlOf(G.root, new byte[] {0, (byte) 0xff}, new byte[] {1, 2}), ROOT_KEY, NOW);
        assertEquals("", r.reason);
        assertEquals(new HashSet<>(Arrays.asList("ff", "102")), r.revoked);
        String[][] rows = {
            {"CRL parse failed: CRL: missing nextUpdate", b64(crl(G.root, tbs(integer(1), THIS, new byte[0], new byte[0])))},
            {"CRL parse failed: CRL: missing nextUpdate", b64(crl(G.root, tbs(integer(1), THIS, new byte[0], revokedList(new byte[] {1}))))},
            {"CRL parse failed: CRL: bad revoked entry", b64(crl(G.root, tbs(integer(1), THIS, NEXT, seq(seq(utc("250101000000Z"))))))},
            {"CRL parse failed: CRL: bad issuer", b64(crl(G.root, seq(integer(1), SIG_ALG_ECDSA_SHA256, octets(new byte[] {1}), THIS, NEXT)))},
            {"CRL parse failed: bad UTCTime", b64(crl(G.root, tbs(integer(1), utc("2603151020Z"), NEXT, new byte[0])))},
            {"CRL parse failed: bad GeneralizedTime", b64(crl(G.root, tbs(integer(1), gen("2026031510Z"), NEXT, new byte[0])))},
            {"CRL parse failed: not a DER time", b64(crl(G.root, tbs(integer(1), octets(new byte[] {1}), NEXT, new byte[0])))},
            {"CRL parse failed: bad GeneralizedTime", b64(crl(G.root, tbs(integer(1), THIS, gen("2027041611Z"), new byte[0])))},
            {"CRL parse failed: CRL: bad TBSCertList", b64(new byte[] {0x30, 0x02, 0x31, 0x00})},
            {"CRL parse failed: CRL: bad outer SEQUENCE", b64(new byte[] {0x30, 0x00, 0x00})},
            {"CRL parse failed: DER bad length", b64(new byte[] {0x30, (byte) 0x80})},
            {"CRL parse failed: DER bad length", b64(new byte[] {0x30, (byte) 0x85, 0, 0, 0, 0, 0})},
            {"CRL parse failed: DER bad length", b64(new byte[] {0x30, (byte) 0x82, 0x01})},
            {"CRL parse failed: DER truncated", b64(new byte[] {0x30, (byte) 0x81, 0x00})},
            {"CRL parse failed: DER truncated", b64(new byte[] {0x30, (byte) 0x84, 0, 0, 0, 0})},
            {"CRL parse failed: DER overrun", b64(new byte[] {0x30, 0x05, 0x00})},
        };
        for (String[] row : rows) assertEquals(row[0], crlReason(Base64.getDecoder().decode(row[1])), row[0]);
        byte[] t = tbs(integer(1), THIS, NEXT, new byte[0]);
        byte[] good = sig(G.root, "SHA256withECDSA", t);
        assertEquals("CRL parse failed: CRL: bad signature", crlReason(seq(t, SIG_ALG_ECDSA_SHA256, octets(good))));
        assertEquals("CRL parse failed: CRL: bad signature", crlReason(seq(t, SIG_ALG_ECDSA_SHA256, bits((byte) 0, good), integer(1))));
        String noSig = "CRL signature does not verify under the issuer";
        assertEquals(noSig, crlReason(seq(t, SIG_ALG_ECDSA_SHA256, withTag(0x03))));
        assertEquals(noSig, crlReason(seq(t, SIG_ALG_ECDSA_SHA256, bits((byte) 0, new byte[] {1, 2, 3}))));
        assertEquals(noSig, crlReason(crlOf(ecKey("secp384r1"))));
        // the issuer key's algorithm picks the verifier: RSA PKCS#1 v1.5, anything else refused
        try {
            KeyPair rsa = RSA;
            CertKey rk = new CertKey(rsa.getPublic(), "rsa", "", rsa.getPublic().getEncoded());
            byte[] rsaCrl = seq(t, SIG_ALG_ECDSA_SHA256, bits((byte) 0, sig(rsa, "SHA256withRSA", t)));
            assertEquals("", AttestNvidiaRim.verifyCrl(rsaCrl, rk, NOW).reason);
            assertEquals(noSig, AttestNvidiaRim.verifyCrl(crlOf(G.root), rk, NOW).reason);
            assertEquals(noSig, AttestNvidiaRim.verifyCrl(seq(t, SIG_ALG_ECDSA_SHA256, bits((byte) 0, new byte[] {1, 2, 3})), rk, NOW).reason);
            KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            CertKey ek = new CertKey(ed.getPublic(), "ed25519", "", ed.getPublic().getEncoded());
            assertEquals(noSig, AttestNvidiaRim.verifyCrl(crlOf(G.root), ek, NOW).reason);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static final KeyPair RSA = rsaKey();

    static KeyPair rsaKey() {
        try {
            KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA");
            rg.initialize(2048);
            return rg.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    @Test
    void chainRevocation() {
        List<String> noIssuers = new ArrayList<>();
        byte[] leafSerial = new byte[] {1, 2}; // every test certificate carries serial 258
        assertEquals("chain certificate 'CN=GH100 A01 FSP BROM' is revoked",
            AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.root, leafSerial)), NOW, noIssuers));
        assertEquals("", AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.root, new byte[] {0x7f})), NOW, noIssuers));
        // a CRL the leaf issued covers no chain certificate
        assertEquals("", AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.leaf, leafSerial)), NOW, noIssuers));
        assertEquals("CRL #0 rejected: CRL signature does not verify under the issuer",
            AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(ecKey("secp384r1"))), NOW, noIssuers));
        assertEquals("CRL #1 rejected: CRL signature does not verify under the issuer",
            AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.root), crlOf(ecKey("secp384r1"))), NOW, noIssuers));
        assertEquals("CRL #0 rejected: CRL is stale (nextUpdate passed)",
            AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.root)), NEXT_MS + 1, noIssuers));
        assertEquals("", AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.root)), NOW, Arrays.asList("NV Root")));
        assertEquals("no verified CRL issued by a certificate matching 'GH100'",
            AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.root)), NOW, Arrays.asList("NV Root", "GH100")));
        assertEquals("", AttestNvidiaRim.checkChainRevocation(CHAIN, Arrays.asList(crlOf(G.root), crlOf(G.leaf)), NOW, Arrays.asList("GH100", "NV Root")));
    }

    // ------------------------------------------------------------- versions and the firmware policy

    static double[] dv(String v) { return AttestNvidiaRim.parseVersion(v, 10); }

    @Test
    void versionOrder() {
        assertEquals(-1, AttestNvidiaRim.cmpVersion(dv("1"), dv("1.1")));
        assertEquals(1, AttestNvidiaRim.cmpVersion(dv("1.1"), dv("1")));
        assertEquals(1, AttestNvidiaRim.cmpVersion(dv("1.2"), dv("1")));
        assertEquals(0, AttestNvidiaRim.cmpVersion(dv("1.0"), dv("1")));
        assertEquals(0, AttestNvidiaRim.cmpVersion(dv("1"), dv("1.0.0")));
        assertEquals(-1, AttestNvidiaRim.cmpVersion(dv("2"), dv("10")));
        assertEquals(1, AttestNvidiaRim.cmpVersion(AttestNvidiaRim.parseVersion("a", 16), AttestNvidiaRim.parseVersion("9", 16)));
        assertEquals(2, dv("1.0").length);
        assertNull(dv("1."));
        assertNull(dv(".1"));
    }

    static AttestNvidiaRim.RimIds ids(String driver, String vbios) {
        AttestNvidiaRim.RimIds ids = new AttestNvidiaRim.RimIds();
        ids.driverVersion = driver;
        ids.vbiosVersion = vbios;
        return ids;
    }

    static AttestNvidiaRim.FirmwarePolicy fw(String json) { return AttestNvidiaRim.FirmwarePolicy.compile(AttestNvidiaTest.cfg(json)); }

    @Test
    void firmwarePolicy() {
        AttestNvidiaRim.FirmwarePolicy empty = fw("{\"minDriverVersion\":\"\",\"minVbiosVersion\":\"\",\"denyDriverVersions\":[1],\"denyVbiosVersions\":\"x\"}");
        assertNull(empty.minD);
        assertNull(empty.minV);
        assertEquals("", empty.check(ids("535.86", "96.00.9f.00.04")));
        assertEquals("driver version 'abc' in the GPU report is not parseable", empty.check(ids("abc", "96.00")));
        assertEquals("VBIOS version '' in the GPU report is not parseable", empty.check(ids("535.86", "")));
        AttestNvidiaRim.FirmwarePolicy p = fw("{\"minDriverVersion\":\"535.86\",\"minVbiosVersion\":\"96.00.9f.00.04\",\"denyDriverVersions\":[\"535.87\"],\"denyVbiosVersions\":[\"96.00.9f.00.05\"]}");
        assertEquals("", p.check(ids("535.86", "96.00.9f.00.04")));
        assertEquals("driver 535.85 is below the minimum 535.86", p.check(ids("535.85", "96.00.9f.00.04")));
        assertEquals("VBIOS 96.00.9f.00.03 is below the minimum 96.00.9f.00.04", p.check(ids("535.86", "96.00.9f.00.03")));
        assertEquals("driver 535.87 is on the deny list", p.check(ids("535.87", "96.00.9f.00.04")));
        assertEquals("VBIOS 96.00.9f.00.05 is on the deny list", p.check(ids("535.86", "96.00.9f.00.05")));
    }

    // ------------------------------------------------------------- the collateral hook

    @Test
    void hookCreate() {
        AttestException e = assertThrows(AttestException.class, () -> AttestNvidiaRim.Hook.create(AttestNvidiaTest.cfg("{\"rimRootSpkiSha256\":[]}")));
        assertEquals("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root", e.getMessage());
        assertNull(AttestNvidiaRim.Hook.create(AttestNvidiaTest.cfg("{\"rimRootSpkiSha256\":[\"aa\"],\"revocation\":5}")).revocation);
        assertNull(AttestNvidiaRim.Hook.create(AttestNvidiaTest.cfg("{\"rimRootSpkiSha256\":[\"aa\"]}")).revocation);
        assertEquals("ocsp", AttestNvidiaRim.Hook.create(AttestNvidiaTest.cfg("{\"rimRootSpkiSha256\":[\"aa\"],\"revocation\":\"ocsp\"}")).revocation);
    }

    static final String DRIVER = sign(doc("GH100", "535.86", m(0, H1)));
    static final String VBIOS = sign(doc("GH100", "96.00.9f.00.04", m(1, H2)));

    static Map<String, Object> bundle(Object driver, Object vbios, List<String> crls, List<String> ocsp) {
        Map<String, Object> c = new HashMap<>();
        if (driver != null) c.put("driverRimXml", driver);
        if (vbios != null) c.put("vbiosRimXml", vbios);
        if (crls != null) c.put("crls", new ArrayList<Object>(crls));
        if (ocsp != null) c.put("ocsp", new ArrayList<Object>(ocsp));
        return c;
    }

    static String run(String extra, Map<String, Object> bundle, List<AttCert> chain) {
        AttestNvidiaRim.Hook h = AttestNvidiaRim.Hook.create(AttestNvidiaTest.cfg("{\"rimRootSpkiSha256\":[\"" + G.pin() + "\"]" + extra + "}"));
        return h.withBundle(bundle).run(fullReport(), chain, NOW);
    }

    static String run(String extra, Object driver, Object vbios) { return run(extra, bundle(driver, vbios, null, null), CHAIN); }

    @Test
    void hookEndToEnd() {
        String none = ",\"revocation\":\"none\"";
        assertEquals("", run(none, DRIVER, VBIOS));
        assertEquals("", run(none, DRIVER, sign(doc("GH100", "96.00.9F.00.04", m(1, H2)))));
        assertEquals("no RIM collateral supplied for this report", run(none, (Map<String, Object>) null, CHAIN));
        assertEquals("driver RIM: RIM: empty or oversized document", run(none, null, VBIOS));
        assertEquals("driver RIM: RIM: empty or oversized document", run(none, 5.0, VBIOS));
        assertEquals("VBIOS RIM: RIM: empty or oversized document", run(none, DRIVER, 5.0));
        assertEquals("VBIOS RIM: RIM: root element is not SoftwareIdentity", run(none, DRIVER, "<a/>"));
        assertEquals("driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)",
            run(none, sign(doc("GB100", "535.86", m(0, H1))), VBIOS));
        assertEquals("VBIOS RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)",
            run(none, DRIVER, sign(doc("GB100", "96.00.9f.00.04", m(1, H2)))));
        assertEquals("driver RIM version '535.87' does not match the report's driver '535.86'", run(none, sign(doc("GH100", "535.87", m(0, H1))), VBIOS));
        assertEquals("VBIOS RIM version '96.00.9f.00.05' does not match the report's VBIOS '96.00.9f.00.04'",
            run(none, DRIVER, sign(doc("GH100", "96.00.9f.00.05", m(1, H2)))));
        assertEquals("runtime measurements differ from the golden RIM values at 1 index(es)", run(none, sign(doc("GH100", "535.86", m(0, H2))), VBIOS));

        // revocation modes
        assertEquals("revocation: no CRLs supplied", run("", DRIVER, VBIOS)); // default: CRLs required
        assertEquals("", run(",\"requireCrls\":false", DRIVER, VBIOS));
        assertEquals("revocation: no CRLs supplied", run(",\"revocation\":\"crl\"", DRIVER, VBIOS));
        assertEquals("revocation: no CRLs supplied", run(",\"revocation\":\"both\"", DRIVER, VBIOS));
        assertEquals("revocation (OCSP): no OCSP responses supplied", run(",\"revocation\":\"ocsp\"", DRIVER, VBIOS));
        String rootCrl = b64(crlOf(G.root));
        assertEquals("revocation (OCSP): no OCSP responses supplied", run(",\"revocation\":\"both\"", bundle(DRIVER, VBIOS, Arrays.asList(rootCrl), null), CHAIN));
        assertEquals("", run(none, bundle(DRIVER, VBIOS, Arrays.asList(rootCrl), null), CHAIN));
        assertEquals("", run(",\"revocation\":\"crl\"", bundle(DRIVER, VBIOS, Arrays.asList(rootCrl), null), CHAIN));
        assertEquals("revocation: CRL #0 rejected: CRL parse failed: DER truncated", run(none, bundle(DRIVER, VBIOS, Arrays.asList("MA=="), null), CHAIN));
        assertEquals("revocation (OCSP): OCSP response #0 for 'CN=GH100 A01 FSP BROM' rejected: response is not valid DER",
            run(none, bundle(DRIVER, VBIOS, null, Arrays.asList("MA==")), CHAIN));

        // the chip-family message renders a multi-RDN subject on one line
        byte[] twoCn = seq(withTag(0x31, seq(oid("2.5.4.3"), utf8("Foo"))), withTag(0x31, seq(oid("2.5.4.3"), utf8("Bar"))));
        List<AttCert> odd = Arrays.asList(AttestCert.parseCertDer(certNamed(twoCn, G.leaf, G.root)), ROOT);
        assertEquals("device leaf subject 'CN=Foo, CN=Bar' is not a GH100 device certificate (chip family mismatch)", run(none, bundle(DRIVER, VBIOS, null, null), odd));
    }

    /** certWithValidity with a raw subject Name. */
    static byte[] certNamed(byte[] subjectName, KeyPair subject, KeyPair signer) {
        byte[] tbs = seq(withTag(0xa0, integer(2)), integer(258), SIG_ALG_ECDSA_SHA256, name("NV Root"),
            seq(utc("250101000000Z"), utc("350101000000Z")), subjectName, subject.getPublic().getEncoded());
        return seq(tbs, SIG_ALG_ECDSA_SHA256, bits((byte) 0, sig(signer, "SHA256withECDSA", tbs)));
    }
}
