package net.atlasauth.pca.abe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;
import org.junit.jupiter.api.Test;

/** Every refusal of the policy normaliser with its exact reason, the node and depth bounds, and the satisfaction and attribute listings. */
class AbePolicyTest {
  private static Map<String, Object> m(Object... kv) {
    Map<String, Object> o = new LinkedHashMap<>();
    for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
    return o;
  }

  private static Map<String, Object> attr(String a) { return m("attr", a); }

  private static String why(Object policy) {
    AbePolicy.Result r = AbePolicy.normalize(policy);
    assertFalse(r.ok(), String.valueOf(policy));
    assertNull(r.tree);
    return r.reason;
  }

  @Test
  void leavesAndGatesNormalise() {
    AbePolicy.Result leaf = AbePolicy.normalize(attr("a"));
    assertTrue(leaf.ok());
    assertNull(leaf.reason);
    assertEquals(AbePolicy.leaf("a"), leaf.tree);
    assertEquals(m("ok", true, "tree", AbePolicy.leaf("a")), leaf.toJson());
    Map<String, Object> all = AbePolicy.normalize(m("allOf", List.of(attr("a"), attr("b"), attr("c")))).tree;
    assertEquals(3L, all.get("t"));
    assertEquals(3, ((List<?>) all.get("of")).size());
    assertEquals(1L, AbePolicy.normalize(m("anyOf", List.of(attr("a"), attr("b")))).tree.get("t"));
    Map<String, Object> th = AbePolicy.normalize(m("threshold", 2, "of", List.of(attr("a"), attr("b"), attr("c")))).tree;
    assertEquals(2L, th.get("t"));
    assertEquals("gate", th.get("kind"));
    assertEquals(2L, AbePolicy.normalize(m("threshold", new Json.Num("2"), "of", List.of(attr("a"), attr("b")))).tree.get("t"));
    assertEquals(2L, AbePolicy.normalize(m("threshold", 2.0, "of", List.of(attr("a"), attr("b")))).tree.get("t"));
    assertEquals(m("ok", false, "reason", "policy: not an object"), AbePolicy.normalize(null).toJson());
  }

  @Test
  void everyMalformedNodeIsRefusedWithItsReason() {
    assertEquals("policy: not an object", why(null));
    assertEquals("policy: not an object", why("a"));
    assertEquals("policy: not an object", why(List.of(attr("a"))));
    assertEquals("policy: 'attr' must be a non-empty string", why(attr("")));
    assertEquals("policy: 'attr' must be a non-empty string", why(m("attr", 5)));
    assertEquals("policy: 'attr' must be a non-empty string", why(m("attr", null)));
    assertEquals("policy: 'attr' is not well-formed UTF-16", why(attr("a\ud800")));
    for (String k : new String[] {"allOf", "anyOf", "threshold", "of"}) {
      assertEquals("policy: a leaf must not mix 'attr' with a gate", why(m("attr", "a", k, List.of(attr("b")))), k);
    }
    assertEquals("policy: unknown policy node (expected attr/allOf/anyOf/threshold)", why(m()));
    assertEquals("policy: unknown policy node (expected attr/allOf/anyOf/threshold)", why(m("of", List.of(attr("a")))));
    assertEquals("policy: unknown policy node (expected attr/allOf/anyOf/threshold)", why(m("x", 1)));
    assertEquals("policy: ambiguous node (allOf, anyOf); a gate must use exactly one of allOf/anyOf/threshold", why(m("allOf", List.of(attr("a")), "anyOf", List.of(attr("a")))));
    assertEquals("policy: ambiguous node (allOf, threshold); a gate must use exactly one of allOf/anyOf/threshold", why(m("allOf", List.of(attr("a")), "threshold", 1)));
    assertEquals("policy: ambiguous node (anyOf, of); a gate must use exactly one of allOf/anyOf/threshold", why(m("anyOf", List.of(attr("a")), "of", List.of(attr("a")))));
    assertEquals("policy: ambiguous node (allOf, anyOf, threshold); a gate must use exactly one of allOf/anyOf/threshold",
        why(m("allOf", List.of(attr("a")), "anyOf", List.of(attr("a")), "threshold", 1, "of", List.of(attr("a")))));
    for (String k : new String[] {"allOf", "anyOf"}) {
      assertEquals("policy: '" + k + "' must be a non-empty array", why(m(k, List.of())), k);
      assertEquals("policy: '" + k + "' must be a non-empty array", why(m(k, "x")), k);
      assertEquals("policy: '" + k + "' must be a non-empty array", why(m(k, null)), k);
    }
    assertEquals("policy: 'of' must be a non-empty array", why(m("threshold", 1)));
    assertEquals("policy: 'of' must be a non-empty array", why(m("threshold", 1, "of", List.of())));
    for (Object t : new Object[] {0, -1, 1.5, "2", Double.NaN, Double.POSITIVE_INFINITY, null, true, new Json.Num("0"), new Json.Num("1.5"), new Json.Num("x"), List.of(2)}) {
      assertEquals("policy: 'threshold' must be a positive integer", why(m("threshold", t, "of", List.of(attr("a"), attr("b")))), String.valueOf(t));
    }
    assertEquals("policy: threshold 4 exceeds the number of branches (3)", why(m("threshold", 4, "of", List.of(attr("a"), attr("b"), attr("c")))));
    assertEquals("policy: threshold 3 exceeds the number of branches (2)", why(m("threshold", 3L, "of", List.of(attr("a"), attr("b")))));
    assertEquals("policy: threshold 100000000000000000000 exceeds the number of branches (2)", why(m("threshold", 1e20, "of", List.of(attr("a"), attr("b")))));
    assertEquals("policy: threshold 123456789012345680000 exceeds the number of branches (1)", why(m("threshold", 123456789012345678901.0, "of", List.of(attr("a")))));
    assertEquals("policy: threshold 1e+21 exceeds the number of branches (1)", why(m("threshold", 1e21, "of", List.of(attr("a")))));
    assertEquals("policy: threshold 1.5e+300 exceeds the number of branches (1)", why(m("threshold", 1.5e300, "of", List.of(attr("a")))));
    assertTrue(AbePolicy.normalize(m("threshold", 3, "of", List.of(attr("a"), attr("b"), attr("c")))).ok(), "threshold == branches is allowed");
    assertEquals("policy.allOf[1]: 'attr' must be a non-empty string", why(m("allOf", List.of(attr("a"), attr("")))));
    assertEquals("policy.anyOf[0].allOf[2]: not an object", why(m("anyOf", List.of(m("allOf", List.of(attr("a"), attr("b"), "x"))))));
    assertEquals("policy.of[1]: not an object", why(m("threshold", 1, "of", List.of(attr("a"), 7))));
  }

  private static Map<String, Object> nested(int gates) {
    Object cur = attr("leaf");
    for (int i = 0; i < gates; i++) cur = m("allOf", List.of(cur));
    @SuppressWarnings("unchecked") Map<String, Object> out = (Map<String, Object>) cur;
    return out;
  }

  @Test
  void theDepthAndNodeBoundsAreExact() {
    assertEquals(10, AbePolicy.MAX_POLICY_DEPTH);
    assertEquals(1024, AbePolicy.MAX_POLICY_NODES);
    assertTrue(AbePolicy.normalize(nested(10)).ok(), "ten nested gates");
    assertEquals("policy" + ".allOf[0]".repeat(10) + ": policy nested deeper than 10 gates", why(nested(11)));
    for (String k : new String[] {"anyOf", "threshold"}) {
      Object cur = attr("leaf");
      for (int i = 0; i < 11; i++) cur = k.equals("anyOf") ? m("anyOf", List.of(cur)) : m("threshold", 1, "of", List.of(cur));
      assertTrue(why(cur).endsWith(": policy nested deeper than 10 gates"), k);
    }
    List<Object> leaves = new ArrayList<>();
    for (int i = 0; i < 1023; i++) leaves.add(attr("a" + i)); // 1023 leaves + the gate = 1024 nodes
    assertTrue(AbePolicy.normalize(m("anyOf", leaves)).ok());
    leaves.add(attr("last"));
    assertEquals("policy too large (> 1024 nodes)", why(m("anyOf", leaves)));
  }

  @Test
  void satisfactionAndAttributeListings() {
    Map<String, Object> tree = AbePolicy.normalize(m("threshold", 2, "of", List.of(attr("b"), attr("a"), m("anyOf", List.of(attr("c"), attr("a")))))).tree;
    assertTrue(AbePolicy.satisfies(tree, Set.of("a", "b")));
    assertTrue(AbePolicy.satisfies(tree, Set.of("a", "c")));
    assertTrue(AbePolicy.satisfies(tree, Set.of("b", "c")));
    assertFalse(AbePolicy.satisfies(tree, Set.of("b")), "one branch of three");
    assertTrue(AbePolicy.satisfies(tree, Set.of("a")), "a is both a leaf and inside the anyOf: two branches");
    assertFalse(AbePolicy.satisfies(tree, Set.of("c")));
    assertFalse(AbePolicy.satisfies(tree, Set.of()));
    assertFalse(AbePolicy.satisfies(tree, Set.of("x", "y")));
    assertTrue(AbePolicy.satisfies(AbePolicy.leaf("a"), Set.of("a")));
    assertFalse(AbePolicy.satisfies(AbePolicy.leaf("a"), Set.of("b")));
    Map<String, Object> all = AbePolicy.normalize(m("allOf", List.of(attr("a"), attr("b")))).tree;
    assertTrue(AbePolicy.satisfies(all, Set.of("a", "b", "z")));
    assertFalse(AbePolicy.satisfies(all, Set.of("a")));
    assertEquals(List.of("a", "b", "c"), AbePolicy.policyAttributes(tree));
    assertEquals(List.of("b", "a", "c", "a"), AbePolicy.leaves(tree), "depth-first, one row per leaf");
    assertEquals(List.of("C", "a", "b"), AbePolicy.policyAttributes(AbePolicy.normalize(m("anyOf", List.of(attr("b"), attr("a"), attr("C"), attr("a")))).tree));
    assertEquals(List.of("z"), AbePolicy.policyAttributes(AbePolicy.leaf("z")));
  }

  @Test
  void numbersAreReadAsJavaScriptReadsThem() {
    assertTrue(AbePolicy.isPosInt(1));
    assertTrue(AbePolicy.isPosInt(2L));
    assertTrue(AbePolicy.isPosInt(3.0));
    assertTrue(AbePolicy.isPosInt(4.0f));
    assertTrue(AbePolicy.isPosInt(new Json.Num("5")));
    assertTrue(AbePolicy.isPosInt(new Json.Num("1e3")));
    assertFalse(AbePolicy.isPosInt(0));
    assertFalse(AbePolicy.isPosInt(-1));
    assertFalse(AbePolicy.isPosInt(0.5));
    assertFalse(AbePolicy.isPosInt(Double.NaN));
    assertFalse(AbePolicy.isPosInt(Double.POSITIVE_INFINITY));
    assertFalse(AbePolicy.isPosInt("1"));
    assertFalse(AbePolicy.isPosInt(null));
    assertFalse(AbePolicy.isPosInt(new Json.Num("nope")));
    assertEquals(1000.0, AbePolicy.num(new Json.Num("1e3")));
    assertEquals(7.0, AbePolicy.num(7));
    assertNull(AbePolicy.num("7"));
    assertEquals("7", AbePolicy.jsInt(7));
    assertEquals("100000000000000000000", AbePolicy.jsInt(1e20));
    assertEquals("123456789012345680000", AbePolicy.jsInt(123456789012345678901.0));
    assertEquals("9007199254740994", AbePolicy.jsInt(9007199254740994.0));
    assertEquals("1e+21", AbePolicy.jsInt(1e21));
    assertEquals("1.5e+22", AbePolicy.jsInt(1.5e22));
  }
}
