// Class Validity
// Dafny class Validity compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Validity {
  public java.math.BigInteger _notBefore;
  public java.math.BigInteger _notAfter;
  public java.math.BigInteger _maxIdle;
  public Validity (java.math.BigInteger notBefore, java.math.BigInteger notAfter, java.math.BigInteger maxIdle) {
    this._notBefore = notBefore;
    this._notAfter = notAfter;
    this._maxIdle = maxIdle;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Validity o = (Validity)other;
    return true && java.util.Objects.equals(this._notBefore, o._notBefore) && java.util.Objects.equals(this._notAfter, o._notAfter) && java.util.Objects.equals(this._maxIdle, o._maxIdle);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._notBefore);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._notAfter);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._maxIdle);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Validity.Validity");
    s.append("(");
    s.append(dafny.Helpers.toString(this._notBefore));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._notAfter));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._maxIdle));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Validity> _TYPE = dafny.TypeDescriptor.<Validity>referenceWithInitializer(Validity.class, () -> Validity.Default());
  public static dafny.TypeDescriptor<Validity> _typeDescriptor() {
    return (dafny.TypeDescriptor<Validity>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Validity theDefault = Validity.create(java.math.BigInteger.ZERO, java.math.BigInteger.ZERO, java.math.BigInteger.ZERO);
  public static Validity Default() {
    return theDefault;
  }
  public static Validity create(java.math.BigInteger notBefore, java.math.BigInteger notAfter, java.math.BigInteger maxIdle) {
    return new Validity(notBefore, notAfter, maxIdle);
  }
  public static Validity create_Validity(java.math.BigInteger notBefore, java.math.BigInteger notAfter, java.math.BigInteger maxIdle) {
    return create(notBefore, notAfter, maxIdle);
  }
  public boolean is_Validity() { return true; }
  public java.math.BigInteger dtor_notBefore() {
    return this._notBefore;
  }
  public java.math.BigInteger dtor_notAfter() {
    return this._notAfter;
  }
  public java.math.BigInteger dtor_maxIdle() {
    return this._maxIdle;
  }
}
