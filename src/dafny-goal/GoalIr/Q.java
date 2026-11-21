// Class Q
// Dafny class Q compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Q {
  public Unit _u;
  public java.math.BigInteger _n;
  public Q (Unit u, java.math.BigInteger n) {
    this._u = u;
    this._n = n;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Q o = (Q)other;
    return true && java.util.Objects.equals(this._u, o._u) && java.util.Objects.equals(this._n, o._n);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._u);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._n);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Q.Q");
    s.append("(");
    s.append(dafny.Helpers.toString(this._u));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._n));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Q> _TYPE = dafny.TypeDescriptor.<Q>referenceWithInitializer(Q.class, () -> Q.Default());
  public static dafny.TypeDescriptor<Q> _typeDescriptor() {
    return (dafny.TypeDescriptor<Q>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Q theDefault = Q.create(Unit.Default(), java.math.BigInteger.ZERO);
  public static Q Default() {
    return theDefault;
  }
  public static Q create(Unit u, java.math.BigInteger n) {
    return new Q(u, n);
  }
  public static Q create_Q(Unit u, java.math.BigInteger n) {
    return create(u, n);
  }
  public boolean is_Q() { return true; }
  public Unit dtor_u() {
    return this._u;
  }
  public java.math.BigInteger dtor_n() {
    return this._n;
  }
}
