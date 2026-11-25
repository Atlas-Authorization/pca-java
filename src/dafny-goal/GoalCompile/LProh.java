// Class LProh
// Dafny class LProh compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class LProh {
  public dafny.DafnySequence<? extends dafny.CodePoint> _pid;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _verbs;
  public GoalIr.ResPat _res;
  public NC _cond;
  public LProh (dafny.DafnySequence<? extends dafny.CodePoint> pid, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs, GoalIr.ResPat res, NC cond) {
    this._pid = pid;
    this._verbs = verbs;
    this._res = res;
    this._cond = cond;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    LProh o = (LProh)other;
    return true && java.util.Objects.equals(this._pid, o._pid) && java.util.Objects.equals(this._verbs, o._verbs) && java.util.Objects.equals(this._res, o._res) && java.util.Objects.equals(this._cond, o._cond);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._pid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verbs);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._res);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._cond);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalCompile.LProh.LProh");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._pid));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._verbs));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._res));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._cond));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<LProh> _TYPE = dafny.TypeDescriptor.<LProh>referenceWithInitializer(LProh.class, () -> LProh.Default());
  public static dafny.TypeDescriptor<LProh> _typeDescriptor() {
    return (dafny.TypeDescriptor<LProh>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final LProh theDefault = LProh.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), GoalIr.ResPat.Default(), NC.Default());
  public static LProh Default() {
    return theDefault;
  }
  public static LProh create(dafny.DafnySequence<? extends dafny.CodePoint> pid, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs, GoalIr.ResPat res, NC cond) {
    return new LProh(pid, verbs, res, cond);
  }
  public static LProh create_LProh(dafny.DafnySequence<? extends dafny.CodePoint> pid, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs, GoalIr.ResPat res, NC cond) {
    return create(pid, verbs, res, cond);
  }
  public boolean is_LProh() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_pid() {
    return this._pid;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_verbs() {
    return this._verbs;
  }
  public GoalIr.ResPat dtor_res() {
    return this._res;
  }
  public NC dtor_cond() {
    return this._cond;
  }
}
