package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * X509_check_issued over extensions on both certificates, and deep input. Each verdict was read from Node 26 checkIssued on a really
 * signed certificate with these exact bytes, on the subject and on the issuer alike. "strict": Node links it, this SDK refuses on purpose.
 */
class K05IssuerLinkTableTest {
    static final KeyPair EC;
    static {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(256);
            EC = g.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static final byte[] KEY_ID = new byte[20];
    static {
        java.util.Arrays.fill(KEY_ID, (byte) 1);
    }
    static final byte[] SKI = ext("2.5.29.14", false, octets(KEY_ID));

    static AttCert parsed(byte[] der) { return AttestCert.parseCertDer(der); }
    static byte[] child(byte[]... exts) { return cert("leaf", "mid", EC, EC, exts); }
    static byte[] ca(byte[]... exts) {
        List<byte[]> all = new ArrayList<>(List.of(SKI));
        all.addAll(List.of(exts));
        return cert("mid", "root", EC, EC, all.toArray(new byte[0][]));
    }

    /** Refused at parse or at the check: both mean no issuer link. */
    static boolean issued(byte[] c, byte[] up) {
        try {
            return AttestNvidiaOcsp.checkIssued(parsed(c), parsed(up));
        } catch (AttestException e) {
            return false;
        }
    }

    static byte[] aki(byte[]... names) {
        return ext("2.5.29.35", false, seq(withTag(0x80, KEY_ID), withTag(0xa1, names)));
    }

    static final String[][] EXT = {
        {"19", "3000", "true"},
        {"19", "30030101ff", "true"},
        {"19", "3003010155", "true"},
        {"19", "3003010100", "true"},
        {"19", "30060101ff020101", "true"},
        {"19", "3003020101", "true"},
        {"19", "30000500", "true"},
        {"19", "30060201010101ff", "false"},
        {"19", "30040102ffff", "false"},
        {"19", "30020100", "false"},
        {"19", "30070101ff02020001", "false"},
        {"19", "30050101ff0200", "false"},
        {"19", "30060101ff0201ff", "false"},
        {"19", "30080101ff0201010500", "false"},
        {"19", "040101", "false"},
        {"15", "0300", "false"},
        {"15", "030100", "false"},
        {"15", "030208a0", "false"},
        {"15", "040100", "false"},
        {"15", "030500", "false"},
        {"15", "", "false"},
        {"37", "300a06082b06010505070301", "true"},
        {"37", "3000", "true"},
        {"37", "3003040101", "false"},
        {"37", "300406028001", "false"},
        {"37", "040101", "false"},
        {"17", "300b860968747470733a2f2f61", "true"},
        {"17", "3000", "true"},
        {"17", "300b860968747470733a2f2f610500", "true"},
        {"17", "300ca00a0603550403a0030c0178", "true"},
        {"17", "300fa00d0603550403a0060c01780c0179", "false"},
        {"17", "3009a0070603550403a000", "false"},
        {"17", "300ea00c0603550403a0030c01780500", "false"},
        {"17", "300ca00a0603550403a1030c0178", "false"},
        {"17", "3003890101", "false"},
        {"17", "3005a403040101", "false"},
        {"17", "040101", "false"},
        {"30", "3007a0053003820161", "true"},
        {"30", "3000", "true"},
        {"30", "300ea0053003820161a1053003820162", "true"},
        {"30", "3002a000", "true"},
        {"30", "300da00b3009820161800100810101", "true"},
        {"30", "300ea1053003820162a0053003820161", "false"},
        {"30", "3005a003040101", "false"},
        {"30", "3004a0023000", "false"},
        {"30", "300da00b3009820161810101800100", "false"},
        {"30", "300ba009300782016180020001", "false"},
        {"30", "3003800101", "false"},
        {"30", "300aa0083006820161820162", "false"},
        {"30", "3005a003820161", "false"},
        {"30", "300aa00830068201618001ff", "strict"},
        {"31", "3011300fa00da00b860968747470733a2f2f61", "true"},
        {"31", "3000", "true"},
        {"31", "3010300ea00ca10a300806035504030c0178", "true"},
        {"31", "300f300da20b860968747470733a2f2f61", "true"},
        {"31", "30153013a00da00b860968747470733a2f2f6181020180", "true"},
        {"31", "30143012a00da00b860968747470733a2f2f61810100", "true"},
        {"31", "30063004a002a000", "true"},
        {"31", "30063004a002a100", "true"},
        {"31", "30023000", "false"},
        {"31", "3003040101", "false"},
        {"31", "30093007a005a103040101", "false"},
        {"31", "3006300481020180", "false"},
        {"31", "30073005a203890101", "false"},
        {"31", "30043002a200", "false"},
        {"31", "301e301ca20b860968747470733a2f2f61a00da00b860968747470733a2f2f61", "false"},
        {"31", "30043002a000", "false"},
        {"31", "3011300fa00da20b860968747470733a2f2f61", "false"},
        {"31", "301e301ca01aa00b860968747470733a2f2f61a00b860968747470733a2f2f61", "false"},
        {"31", "30093007a005a003890101", "false"},
        {"31", "30153013a00da00b860968747470733a2f2f6181020880", "false"},
        {"31", "30133011a00da00b860968747470733a2f2f618100", "false"},
    };

    /** later: this [4] directoryName after the one that matches; withNames: this GeneralName before it. */
    static final String[][] NAMES = {
        {"later", "a4023000", "true"},
        {"later", "a40430023100", "true"},
        {"later", "a4123010310e300c06035504030c056c61746572", "true"},
        {"later", "a40d300b3109300706035504030c00", "true"},
        {"later", "a40f300d310b300906035504031302c3a9", "true"},
        {"later", "a40e300c310a300806035504031601e9", "true"},
        {"later", "a40e300c310a300806035504031401e9", "true"},
        {"later", "a41830163114300806035504060c0162300806035504030c0161", "true"},
        {"later", "a41a3018310a300806035504030c0161310a300806035504030c0162", "true"},
        {"later", "a40430023000", "false"},
        {"later", "a40730053103040101", "false"},
        {"later", "a40b3009310730050603550403", "false"},
        {"later", "a406300431023000", "false"},
        {"later", "a40c300a310830060401010c0178", "false"},
        {"later", "a411300f310d300b06035504030c01780c0179", "false"},
        {"later", "a40b30093107300506000c0178", "false"},
        {"later", "a40d300b31093007060280010c0178", "false"},
        {"later", "a40d300b31093007060255840c0178", "false"},
        {"later", "a40e300c310a300806035580010c0178", "false"},
        {"later", "a40e300c310a30080603550403020101", "false"},
        {"later", "a40d300b3109300706035504030500", "false"},
        {"later", "a40f300d310b300906035504030c02c328", "false"},
        {"later", "a410300e310c300a06035504031e03004100", "false"},
        {"later", "a410300e310c300a06035504031c03000041", "false"},
        {"later", "a40f300d310b300906035504030c096161", "false"},
        {"later", "a411300f310d300806035504030c0178040101", "false"},
        {"later", "a40d300b3109300706035504033000", "strict"},
        {"later", "a40f300d310b300906035504031e020041", "strict"},
        {"withNames", "a00a0603550403a0030c0178", "true"},
        {"withNames", "8101e9", "true"},
        {"withNames", "8201e9", "true"},
        {"withNames", "8200", "true"},
        {"withNames", "8601e9", "true"},
        {"withNames", "8703010203", "true"},
        {"withNames", "8700", "true"},
        {"withNames", "a003040101", "false"},
        {"withNames", "a000", "false"},
        {"withNames", "a0050603550403", "false"},
        {"withNames", "a008040101a0030c0178", "false"},
        {"withNames", "8800", "false"},
        {"withNames", "88028001", "false"},
        {"withNames", "a500", "false"},
        {"withNames", "a503040101", "false"},
        {"withNames", "a400", "false"},
        {"withNames", "830101", "false"},
        {"withNames", "840101", "false"},
        {"withNames", "850101", "false"},
        {"withNames", "a800", "false"},
        {"withNames", "8803550403", "true"},
        {"withNames", "a300", "strict"},
        {"withNames", "a303020101", "strict"},
        {"withNames", "a505a1030c0178", "strict"},
        {"withNames", "a203160141", "strict"},
        {"withNames", "a600", "strict"},
        {"withNames", "a700", "strict"},
        {"withNames", "a100", "strict"},
    };

    static boolean want(String v) { return v.equals("true"); }

    @Test void aCachedExtensionDecodesOnBothCertificates() {
        for (String[] r : EXT) {
            byte[] e = ext("2.5.29." + r[0], false, HexFormat.of().parseHex(r[1]));
            assertEquals(want(r[2]), issued(child(e), ca()), "subject " + r[0] + " " + r[1]);
            assertEquals(want(r[2]), issued(child(), ca(e)), "issuer " + r[0] + " " + r[1]);
        }
    }

    @Test void everyNameInsideAnAkidDecodes() {
        byte[] root = withTag(0xa4, name("root"));
        assertTrue(issued(child(aki(root)), ca()));
        assertFalse(issued(child(aki(withTag(0xa4, name("other")))), ca()));
        for (String[] r : NAMES) {
            byte[] n = HexFormat.of().parseHex(r[1]);
            byte[] e = r[0].equals("later") ? aki(root, n) : aki(n, root);
            assertEquals(want(r[2]), issued(child(e), ca()), r[0] + " " + r[1]);
        }
    }

    @Test void aProxyCertInfoAndARepeatedExtensionAreRefused() {
        byte[] pci = ext("1.3.6.1.5.5.7.1.14", false, seq(seq(oid("1.3.6.1.5.5.7.21.1"))));
        assertFalse(issued(child(pci), ca()));
        assertFalse(issued(child(), ca(pci)));
        byte[] unknown = ext("2.5.29.99", false, new byte[] {1});
        assertTrue(issued(child(unknown), ca(unknown)));
        assertFalse(issued(child(unknown, unknown), ca()));
        assertFalse(issued(child(), ca(unknown, unknown)));
    }

    /** A very deep document is an ordinary refusal on every JSON path, never a StackOverflowError. */
    @Test void deepJsonIsRefusedNotACrash() {
        String deep = "[".repeat(1_000_000);
        assertThrows(IllegalArgumentException.class, () -> Json.parse(deep));
        assertThrows(IllegalArgumentException.class, () -> Json.parseLenient(deep));
        assertEquals("JSON nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.parseLenient(deep)).getMessage());
        String cursor = Base64.getUrlEncoder().withoutPadding().encodeToString(deep.getBytes(StandardCharsets.UTF_8)) + ".x";
        assertEquals("malformed", K3.verifyListCursor(cursor, "s", Map.of()).reason);
    }

    /** DER readers walk one level per call, so a deep tower needs no recursion. */
    @Test void deepDerIsRefusedNotACrash() {
        byte[] v = new byte[0];
        for (int i = 0; i < 5_000; i++) v = withTag(0x30, v);
        byte[] deep = v;
        assertFalse(issued(child(ext("2.5.29.17", false, deep)), ca()), "not a GeneralName");
        assertFalse(issued(child(ext("2.5.29.30", false, deep)), ca()));
    }
}
