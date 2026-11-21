// Class LPred
// Dafny class LPred compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class LPred {
  public dafny.DafnySequence<? extends dafny.CodePoint> _gid;
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public GoalIr.ResPat _res;
  public NC _cond;
  public LPred (dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb, GoalIr.ResPat res, NC cond) {
    this._gid = gid;
    this._verb = verb;
    this._res = res;
    this._cond = cond;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    LPred o = (LPred)other;
    return true && java.util.Objects.equals(this._gid, o._gid) && java.util.Objects.equals(this._verb, o._verb) && java.util.Objects.equals(this._res, o._res) && java.util.Objects.equals(this._cond, o._cond);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._gid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verb);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._res);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._cond);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalCompile.LPred.LPred");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._gid));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._verb));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._res));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._cond));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<LPred> _TYPE = dafny.TypeDescriptor.<LPred>referenceWithInitializer(LPred.class, () -> LPred.Default());
  public static dafny.TypeDescriptor<LPred> _typeDescriptor() {
    return (dafny.TypeDescriptor<LPred>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final LPred theDefault = LPred.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.ResPat.Default(), NC.Default());
  public static LPred Default() {
    return theDefault;
  }
  public static LPred create(dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb, GoalIr.ResPat res, NC cond) {
    return new LPred(gid, verb, res, cond);
  }
  public static LPred create_LPred(dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb, GoalIr.ResPat res, NC cond) {
    return create(gid, verb, res, cond);
  }
  public boolean is_LPred() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_gid() {
    return this._gid;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    return this._verb;
  }
  public GoalIr.ResPat dtor_res() {
    return this._res;
  }
  public NC dtor_cond() {
    return this._cond;
  }
}
