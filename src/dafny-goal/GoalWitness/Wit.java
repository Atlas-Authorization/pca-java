// Class Wit
// Dafny class Wit compiled into Java
package GoalWitness;

@SuppressWarnings({"unchecked", "deprecation"})
public class Wit {
  public dafny.DafnySequence<? extends dafny.CodePoint> _gid;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _bids;
  public Wit (dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> bids) {
    this._gid = gid;
    this._bids = bids;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Wit o = (Wit)other;
    return true && java.util.Objects.equals(this._gid, o._gid) && java.util.Objects.equals(this._bids, o._bids);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._gid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._bids);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalWitness.Wit.Wit");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._gid));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._bids));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Wit> _TYPE = dafny.TypeDescriptor.<Wit>referenceWithInitializer(Wit.class, () -> Wit.Default());
  public static dafny.TypeDescriptor<Wit> _typeDescriptor() {
    return (dafny.TypeDescriptor<Wit>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Wit theDefault = Wit.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
  public static Wit Default() {
    return theDefault;
  }
  public static Wit create(dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> bids) {
    return new Wit(gid, bids);
  }
  public static Wit create_Wit(dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> bids) {
    return create(gid, bids);
  }
  public boolean is_Wit() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_gid() {
    return this._gid;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_bids() {
    return this._bids;
  }
}
