// Class Grant
// Dafny class Grant compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Grant {
  public dafny.DafnySequence<? extends dafny.CodePoint> _gid;
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public ResSel _res;
  public Cond _cond;
  public Grant (dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb, ResSel res, Cond cond) {
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
    Grant o = (Grant)other;
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
    s.append("GoalIr.Grant.Grant");
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
  private static final dafny.TypeDescriptor<Grant> _TYPE = dafny.TypeDescriptor.<Grant>referenceWithInitializer(Grant.class, () -> Grant.Default());
  public static dafny.TypeDescriptor<Grant> _typeDescriptor() {
    return (dafny.TypeDescriptor<Grant>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Grant theDefault = Grant.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), ResSel.Default(), Cond.Default());
  public static Grant Default() {
    return theDefault;
  }
  public static Grant create(dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb, ResSel res, Cond cond) {
    return new Grant(gid, verb, res, cond);
  }
  public static Grant create_Grant(dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb, ResSel res, Cond cond) {
    return create(gid, verb, res, cond);
  }
  public boolean is_Grant() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_gid() {
    return this._gid;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    return this._verb;
  }
  public ResSel dtor_res() {
    return this._res;
  }
  public Cond dtor_cond() {
    return this._cond;
  }
}
