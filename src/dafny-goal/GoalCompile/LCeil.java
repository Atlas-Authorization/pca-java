// Class LCeil
// Dafny class LCeil compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class LCeil {
  public dafny.DafnySequence<? extends dafny.CodePoint> _bid;
  public GoalIr.LSel _sel;
  public GoalIr.BCore _core;
  public LCeil (dafny.DafnySequence<? extends dafny.CodePoint> bid, GoalIr.LSel sel, GoalIr.BCore core) {
    this._bid = bid;
    this._sel = sel;
    this._core = core;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    LCeil o = (LCeil)other;
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
    s.append("GoalCompile.LCeil.LCeil");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._bid));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._sel));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._core));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<LCeil> _TYPE = dafny.TypeDescriptor.<LCeil>referenceWithInitializer(LCeil.class, () -> LCeil.Default());
  public static dafny.TypeDescriptor<LCeil> _typeDescriptor() {
    return (dafny.TypeDescriptor<LCeil>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final LCeil theDefault = LCeil.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.LSel.Default(), GoalIr.BCore.Default());
  public static LCeil Default() {
    return theDefault;
  }
  public static LCeil create(dafny.DafnySequence<? extends dafny.CodePoint> bid, GoalIr.LSel sel, GoalIr.BCore core) {
    return new LCeil(bid, sel, core);
  }
  public static LCeil create_LCeil(dafny.DafnySequence<? extends dafny.CodePoint> bid, GoalIr.LSel sel, GoalIr.BCore core) {
    return create(bid, sel, core);
  }
  public boolean is_LCeil() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_bid() {
    return this._bid;
  }
  public GoalIr.LSel dtor_sel() {
    return this._sel;
  }
  public GoalIr.BCore dtor_core() {
    return this._core;
  }
}
