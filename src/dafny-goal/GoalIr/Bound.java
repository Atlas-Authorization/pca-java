// Class Bound
// Dafny class Bound compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Bound {
  public dafny.DafnySequence<? extends dafny.CodePoint> _bid;
  public Sel _sel;
  public BCore _core;
  public Bound (dafny.DafnySequence<? extends dafny.CodePoint> bid, Sel sel, BCore core) {
    this._bid = bid;
    this._sel = sel;
    this._core = core;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Bound o = (Bound)other;
    return true && java.util.Objects.equals(this._bid, o._bid) && java.util.Objects.equals(this._sel, o._sel) && java.util.Objects.equals(this._core, o._core);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._bid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._sel);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._core);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Bound.Bound");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._bid));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._sel));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._core));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Bound> _TYPE = dafny.TypeDescriptor.<Bound>referenceWithInitializer(Bound.class, () -> Bound.Default());
  public static dafny.TypeDescriptor<Bound> _typeDescriptor() {
    return (dafny.TypeDescriptor<Bound>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Bound theDefault = Bound.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), Sel.Default(), BCore.Default());
  public static Bound Default() {
    return theDefault;
  }
  public static Bound create(dafny.DafnySequence<? extends dafny.CodePoint> bid, Sel sel, BCore core) {
    return new Bound(bid, sel, core);
  }
  public static Bound create_Bound(dafny.DafnySequence<? extends dafny.CodePoint> bid, Sel sel, BCore core) {
    return create(bid, sel, core);
  }
  public boolean is_Bound() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_bid() {
    return this._bid;
  }
  public Sel dtor_sel() {
    return this._sel;
  }
  public BCore dtor_core() {
    return this._core;
  }
}
