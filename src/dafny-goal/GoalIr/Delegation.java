// Class Delegation
// Dafny class Delegation compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Delegation {
  public java.math.BigInteger _maxDepth;
  public boolean _narrowOnly;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _mayTouch;
  public Delegation (java.math.BigInteger maxDepth, boolean narrowOnly, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> mayTouch) {
    this._maxDepth = maxDepth;
    this._narrowOnly = narrowOnly;
    this._mayTouch = mayTouch;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Delegation o = (Delegation)other;
    return true && java.util.Objects.equals(this._maxDepth, o._maxDepth) && this._narrowOnly == o._narrowOnly && java.util.Objects.equals(this._mayTouch, o._mayTouch);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._maxDepth);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._narrowOnly);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._mayTouch);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Delegation.Delegation");
    s.append("(");
    s.append(dafny.Helpers.toString(this._maxDepth));
    s.append(", ");
    s.append(this._narrowOnly);
    s.append(", ");
    s.append(dafny.Helpers.toString(this._mayTouch));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Delegation> _TYPE = dafny.TypeDescriptor.<Delegation>referenceWithInitializer(Delegation.class, () -> Delegation.Default());
  public static dafny.TypeDescriptor<Delegation> _typeDescriptor() {
    return (dafny.TypeDescriptor<Delegation>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Delegation theDefault = Delegation.create(java.math.BigInteger.ZERO, false, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
  public static Delegation Default() {
    return theDefault;
  }
  public static Delegation create(java.math.BigInteger maxDepth, boolean narrowOnly, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> mayTouch) {
    return new Delegation(maxDepth, narrowOnly, mayTouch);
  }
  public static Delegation create_Delegation(java.math.BigInteger maxDepth, boolean narrowOnly, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> mayTouch) {
    return create(maxDepth, narrowOnly, mayTouch);
  }
  public boolean is_Delegation() { return true; }
  public java.math.BigInteger dtor_maxDepth() {
    return this._maxDepth;
  }
  public boolean dtor_narrowOnly() {
    return this._narrowOnly;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_mayTouch() {
    return this._mayTouch;
  }
}
