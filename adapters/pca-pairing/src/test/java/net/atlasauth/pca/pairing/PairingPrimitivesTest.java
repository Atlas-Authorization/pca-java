package net.atlasauth.pca.pairing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import supranational.blst.P1;
import supranational.blst.P2;

/** Group laws of the GT shim and the blst helpers, checked against independent models (bilinearity, RFC 9380 expand_message_xmd, modular arithmetic). */
class PairingPrimitivesTest {
  private static final BigInteger R = Bls12.R;
  private static final BigInteger A = BigInteger.valueOf(7), B = BigInteger.valueOf(11);

  private static P1 g1() { return P1.generator(); }

  private static P2 g2() { return P2.generator(); }

  private static byte[] ff(int n) { byte[] b = new byte[n]; Arrays.fill(b, (byte) 0xff); return b; }

  @Test
  void pairingIsBilinearAndGtIsAGroup() {
    byte[] e = Gt.pairing(g1(), g2());
    assertEquals(Gt.BYTES, e.length);
    assertEquals(576, Gt.BYTES);
    assertTrue(Gt.isElement(e));
    byte[] eab = Gt.pairing(Bls12.mul(g1(), A), Bls12.mul(g2(), B));
    assertArrayEquals(Gt.pow(e, A.multiply(B)), eab);
    assertArrayEquals(Gt.pairing(Bls12.mul(g1(), A.multiply(B)), g2()), eab);
    assertArrayEquals(Gt.pairing(g1(), Bls12.mul(g2(), A.multiply(B))), eab);
    assertArrayEquals(Gt.mul(e, e), Gt.pow(e, BigInteger.TWO));
    assertArrayEquals(Gt.mul(Gt.pow(e, A), Gt.pow(e, B)), Gt.pow(e, A.add(B)));
    assertArrayEquals(e, Gt.pow(e, BigInteger.ONE));
    assertArrayEquals(e, Gt.pow(e, R.add(BigInteger.ONE)), "the exponent is taken mod r");
    assertArrayEquals(Gt.pow(e, R.subtract(BigInteger.ONE)), Gt.pow(e, BigInteger.valueOf(-1)), "a negative exponent wraps to r-1");
    byte[] id = Gt.pow(e, R);
    assertFalse(Gt.isElement(id), "the identity is not accepted as an element");
    assertArrayEquals(id, Gt.mul(Gt.pow(e, BigInteger.valueOf(-1)), e));
    assertArrayEquals(e, Gt.mul(id, e));
    assertArrayEquals(e, Gt.mul(e, id));
    assertFalse(Arrays.equals(e, Gt.pow(e, BigInteger.TWO)));
    assertArrayEquals(Gt.mul(e, e), Gt.pairingProduct(List.of(g1(), g1()), List.of(g2(), g2())));
    assertArrayEquals(Gt.mul(Gt.pairing(Bls12.mul(g1(), A), g2()), Gt.pairing(g1(), Bls12.mul(g2(), B))),
        Gt.pairingProduct(List.of(Bls12.mul(g1(), A), g1()), List.of(g2(), Bls12.mul(g2(), B))));
  }

  @Test
  void gtRefusesNonCanonicalOperandsAndDegenerateProducts() {
    byte[] e = Gt.pairing(g1(), g2());
    byte[] junk = ff(Gt.BYTES);
    assertFalse(Gt.isElement(null));
    assertFalse(Gt.isElement(new byte[0]));
    assertFalse(Gt.isElement(Arrays.copyOf(e, Gt.BYTES - 1)));
    assertFalse(Gt.isElement(Arrays.copyOf(e, Gt.BYTES + 1)));
    assertFalse(Gt.isElement(junk));
    assertThrows(IllegalArgumentException.class, () -> Gt.mul(junk, e));
    assertThrows(IllegalArgumentException.class, () -> Gt.mul(e, junk));
    assertThrows(IllegalArgumentException.class, () -> Gt.pow(junk, A));
    assertThrows(IllegalArgumentException.class, () -> Gt.pairingProduct(List.of(), List.of()));
    assertThrows(IllegalArgumentException.class, () -> Gt.pairingProduct(List.of(g1()), List.of()));
    assertThrows(IllegalArgumentException.class, () -> Gt.pairingProduct(List.of(g1()), List.of(g2(), g2())));
    assertThrows(IllegalArgumentException.class, () -> Gt.pairing(new P1(), g2()));
    assertThrows(IllegalArgumentException.class, () -> Gt.pairing(g1(), new P2()));
    assertThrows(IllegalArgumentException.class, () -> Gt.pairingProduct(List.of(g1(), new P1()), List.of(g2(), g2())));
    assertThrows(IllegalArgumentException.class, () -> Gt.pairingProduct(List.of(g1(), g1()), List.of(g2(), new P2())));
  }

  @Test
  void scalarArithmeticIsModuloR() {
    assertEquals(R.subtract(BigInteger.ONE), Bls12.mod(BigInteger.valueOf(-1)));
    assertEquals(BigInteger.ZERO, Bls12.mod(R));
    assertEquals(BigInteger.valueOf(3), Bls12.add(R.subtract(BigInteger.ONE), BigInteger.valueOf(4)));
    assertEquals(R.subtract(BigInteger.ONE), Bls12.sub(BigInteger.ZERO, BigInteger.ONE));
    assertEquals(BigInteger.valueOf(3), Bls12.sub(BigInteger.valueOf(5), BigInteger.TWO));
    assertEquals(BigInteger.valueOf(2), Bls12.mul(R.add(BigInteger.ONE), BigInteger.TWO));
    assertEquals(BigInteger.valueOf(6), Bls12.mul(BigInteger.TWO, BigInteger.valueOf(3)));
    for (long x : new long[] {1, 2, 12345}) assertEquals(BigInteger.ONE, Bls12.mul(Bls12.inv(BigInteger.valueOf(x)), BigInteger.valueOf(x)));
    assertEquals(BigInteger.ONE, Bls12.inv(R.add(BigInteger.ONE)), "inv reduces its argument first");
    assertEquals(R.subtract(BigInteger.ONE), Bls12.inv(R.subtract(BigInteger.ONE)));
    assertThrows(ArithmeticException.class, () -> Bls12.inv(BigInteger.ZERO));
    assertThrows(ArithmeticException.class, () -> Bls12.inv(R));
  }

  @Test
  void i2ospAndOs2ipAreFixedWidthBigEndian() {
    assertArrayEquals(new byte[] {0, 0, 0, 1}, Bls12.i2osp(BigInteger.ONE, 4));
    assertArrayEquals(new byte[] {(byte) 0xff}, Bls12.i2osp(BigInteger.valueOf(255), 1));
    assertArrayEquals(new byte[] {1, 0}, Bls12.i2osp(BigInteger.valueOf(256), 2));
    assertArrayEquals(new byte[3], Bls12.i2osp(BigInteger.ZERO, 3));
    assertThrows(IllegalArgumentException.class, () -> Bls12.i2osp(BigInteger.valueOf(256), 1));
    assertThrows(IllegalArgumentException.class, () -> Bls12.i2osp(BigInteger.ONE, 0));
    assertThrows(IllegalArgumentException.class, () -> Bls12.i2osp(BigInteger.valueOf(-1), 4));
    assertEquals(32, Bls12.i2osp(R.subtract(BigInteger.ONE), 32).length);
    assertEquals(BigInteger.valueOf(0x0102), Bls12.os2ip(new byte[] {1, 2}));
    assertEquals(BigInteger.valueOf(255), Bls12.os2ip(new byte[] {(byte) 0xff}), "unsigned");
    assertEquals(R.subtract(BigInteger.ONE), Bls12.os2ip(Bls12.i2osp(R.subtract(BigInteger.ONE), 32)));
  }

  @Test
  void pointMultiplicationAndGroupOperations() {
    P1 p = g1();
    byte[] before = p.compress();
    assertTrue(Bls12.mul(p, BigInteger.ZERO).is_inf());
    assertTrue(Bls12.mul(p, R).is_inf());
    assertArrayEquals(before, Bls12.mul(p, BigInteger.ONE).compress());
    assertArrayEquals(before, Bls12.mul(p, R.add(BigInteger.ONE)).compress());
    assertArrayEquals(Bls12.add(p, p).compress(), Bls12.mul(p, BigInteger.TWO).compress());
    assertArrayEquals(Bls12.mul(p, A.add(B)).compress(), Bls12.add(Bls12.mul(p, A), Bls12.mul(p, B)).compress());
    assertTrue(Bls12.sub(p, p).is_inf());
    assertArrayEquals(Bls12.mul(p, A).compress(), Bls12.sub(Bls12.mul(p, A.add(B)), Bls12.mul(p, B)).compress());
    assertArrayEquals(Bls12.mul(p, R.subtract(BigInteger.ONE)).compress(), Bls12.sub(new P1(), p).compress());
    assertArrayEquals(before, p.compress(), "the operand is not modified");
    P2 q = g2();
    byte[] qb = q.compress();
    assertTrue(Bls12.mul(q, BigInteger.ZERO).is_inf());
    assertTrue(Bls12.mul(q, R).is_inf());
    assertArrayEquals(qb, Bls12.mul(q, BigInteger.ONE).compress());
    assertArrayEquals(Bls12.add(q, q).compress(), Bls12.mul(q, BigInteger.TWO).compress());
    assertArrayEquals(qb, q.compress());
    assertFalse(Arrays.equals(Bls12.mul(p, A).compress(), Bls12.mul(p, B).compress()));
  }

  @Test
  void pointDecodingIsStrict() {
    P1 p = Bls12.mul(g1(), A);
    assertArrayEquals(p.compress(), Bls12.decodeG1(p.compress()).compress());
    P2 q = Bls12.mul(g2(), B);
    assertArrayEquals(q.compress(), Bls12.decodeG2(q.compress()).compress());
    byte[] g1b = p.compress(), g2b = q.compress();
    byte[] uncompressed1 = g1b.clone(), uncompressed2 = g2b.clone();
    uncompressed1[0] &= 0x7f;
    uncompressed2[0] &= 0x7f;
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG1(null));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG1(Arrays.copyOf(g1b, 47)));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG1(Arrays.copyOf(g1b, 49)));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG1(uncompressed1));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG1(ff(48)));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG2(null));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG2(Arrays.copyOf(g2b, 95)));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG2(Arrays.copyOf(g2b, 97)));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG2(uncompressed2));
    assertThrows(IllegalArgumentException.class, () -> Bls12.decodeG2(ff(96)));
  }

  @Test
  void pairingEqualityDecidesBilinearRelations() {
    assertTrue(Bls12.pairingEq(Bls12.mul(g1(), A), g2(), g1(), Bls12.mul(g2(), A)));
    assertTrue(Bls12.pairingEq(Bls12.mul(g1(), A.multiply(B)), g2(), Bls12.mul(g1(), B), Bls12.mul(g2(), A)));
    assertFalse(Bls12.pairingEq(g1(), g2(), g1(), Bls12.mul(g2(), BigInteger.TWO)));
    assertFalse(Bls12.pairingEq(Bls12.mul(g1(), A), g2(), g1(), Bls12.mul(g2(), B)));
  }

  /** RFC 9380 5.3.1 written straight from the text (len >= 1). */
  private static byte[] xmd(byte[] msg, byte[] dst, int len) throws Exception {
    MessageDigest h = MessageDigest.getInstance("SHA-256");
    int ell = (len + 31) / 32;
    byte[] dstPrime = Arrays.copyOf(dst, dst.length + 1);
    dstPrime[dst.length] = (byte) dst.length;
    h.update(new byte[64]);
    h.update(msg);
    h.update(new byte[] {(byte) (len >> 8), (byte) len, 0});
    h.update(dstPrime);
    byte[] b0 = h.digest();
    byte[][] b = new byte[ell + 1][];
    h.update(b0);
    h.update((byte) 1);
    h.update(dstPrime);
    b[1] = h.digest();
    for (int i = 2; i <= ell; i++) {
      byte[] x = new byte[32];
      for (int k = 0; k < 32; k++) x[k] = (byte) (b0[k] ^ b[i - 1][k]);
      h.update(x);
      h.update((byte) i);
      h.update(dstPrime);
      b[i] = h.digest();
    }
    byte[] all = new byte[ell * 32];
    for (int i = 1; i <= ell; i++) System.arraycopy(b[i], 0, all, (i - 1) * 32, 32);
    return Arrays.copyOf(all, len);
  }

  @Test
  void expandMessageXmdMatchesTheRfcAndAnIndependentModel() throws Exception {
    byte[] dst = "QUUX-V01-CS02-with-expander-SHA256-128".getBytes(StandardCharsets.US_ASCII);
    assertEquals("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235", HexFormat.of().formatHex(Bls12.expandMessageXmd(new byte[0], dst, 32)));
    for (int len : new int[] {1, 31, 32, 33, 64, 65, 96, 128, 255, 1000}) {
      for (String msg : new String[] {"", "abc", "abcdef0123456789"}) {
        byte[] m = msg.getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(xmd(m, dst, len), Bls12.expandMessageXmd(m, dst, len), msg + "/" + len);
      }
    }
    byte[] longDst = new byte[255];
    Arrays.fill(longDst, (byte) 'd');
    assertArrayEquals(xmd(new byte[] {1}, longDst, 70), Bls12.expandMessageXmd(new byte[] {1}, longDst, 70));
    assertEquals(0, Bls12.expandMessageXmd(new byte[0], dst, 0).length);
    assertEquals(255 * 32, Bls12.expandMessageXmd(new byte[0], dst, 255 * 32).length);
    assertThrows(IllegalArgumentException.class, () -> Bls12.expandMessageXmd(new byte[0], dst, 255 * 32 + 1));
    assertThrows(IllegalArgumentException.class, () -> Bls12.expandMessageXmd(new byte[0], dst, 65536));
    assertThrows(IllegalArgumentException.class, () -> Bls12.expandMessageXmd(new byte[0], dst, -1));
    assertThrows(IllegalArgumentException.class, () -> Bls12.expandMessageXmd(new byte[0], new byte[256], 32));
    assertFalse(Arrays.equals(Bls12.expandMessageXmd(new byte[] {1}, dst, 32), Bls12.expandMessageXmd(new byte[] {2}, dst, 32)));
    assertFalse(Arrays.equals(Bls12.expandMessageXmd(new byte[] {1}, dst, 32), Bls12.expandMessageXmd(new byte[] {1}, longDst, 32)));
  }
}
