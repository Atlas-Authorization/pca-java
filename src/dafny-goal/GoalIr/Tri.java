// Class Tri
// Dafny class Tri compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Tri {
  public Tri() {
  }
  public static boolean _Is(java.math.BigInteger __source) {
    java.math.BigInteger _1_t = __source;
    return ((_1_t).signum() != -1) && ((_1_t).compareTo(java.math.BigInteger.valueOf(2L)) <= 0);
  }
  private static final dafny.TypeDescriptor<java.math.BigInteger> _TYPE = dafny.TypeDescriptor.<java.math.BigInteger>referenceWithInitializer(java.math.BigInteger.class, () -> java.math.BigInteger.ZERO);
  public static dafny.TypeDescriptor<java.math.BigInteger> _typeDescriptor() {
    return (dafny.TypeDescriptor<java.math.BigInteger>) (dafny.TypeDescriptor<?>) _TYPE;
  }
}
