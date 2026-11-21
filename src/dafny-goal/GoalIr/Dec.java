// Class Dec
// Dafny class Dec compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Dec {
  public Dec() {
  }
  public static boolean _Is(java.math.BigInteger __source) {
    java.math.BigInteger _0_d = __source;
    return ((_0_d).signum() != -1) && ((_0_d).compareTo(java.math.BigInteger.valueOf(2L)) <= 0);
  }
  private static final dafny.TypeDescriptor<java.math.BigInteger> _TYPE = dafny.TypeDescriptor.<java.math.BigInteger>referenceWithInitializer(java.math.BigInteger.class, () -> java.math.BigInteger.ZERO);
  public static dafny.TypeDescriptor<java.math.BigInteger> _typeDescriptor() {
    return (dafny.TypeDescriptor<java.math.BigInteger>) (dafny.TypeDescriptor<?>) _TYPE;
  }
}
