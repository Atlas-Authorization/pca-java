// Class Prohibit
// Dafny class Prohibit compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Prohibit {
  public dafny.DafnySequence<? extends dafny.CodePoint> _pid;
  public ProhTarget _target;
  public ResSel _res;
  public Cond _cond;
  public Prohibit (dafny.DafnySequence<? extends dafny.CodePoint> pid, ProhTarget target, ResSel res, Cond cond) {
    this._pid = pid;
    this._target = target;
    this._res = res;
    this._cond = cond;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Prohibit o = (Prohibit)other;
    return true && java.util.Objects.equals(this._pid, o._pid) && java.util.Objects.equals(this._target, o._target) && java.util.Objects.equals(this._res, o._res) && java.util.Objects.equals(this._cond, o._cond);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._pid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._target);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._res);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._cond);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Prohibit.Prohibit");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._pid));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._target));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._res));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._cond));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Prohibit> _TYPE = dafny.TypeDescriptor.<Prohibit>referenceWithInitializer(Prohibit.class, () -> Prohibit.Default());
  public static dafny.TypeDescriptor<Prohibit> _typeDescriptor() {
    return (dafny.TypeDescriptor<Prohibit>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Prohibit theDefault = Prohibit.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), ProhTarget.Default(), ResSel.Default(), Cond.Default());
  public static Prohibit Default() {
    return theDefault;
  }
  public static Prohibit create(dafny.DafnySequence<? extends dafny.CodePoint> pid, ProhTarget target, ResSel res, Cond cond) {
    return new Prohibit(pid, target, res, cond);
  }
  public static Prohibit create_Prohibit(dafny.DafnySequence<? extends dafny.CodePoint> pid, ProhTarget target, ResSel res, Cond cond) {
    return create(pid, target, res, cond);
  }
  public boolean is_Prohibit() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_pid() {
    return this._pid;
  }
  public ProhTarget dtor_target() {
    return this._target;
  }
  public ResSel dtor_res() {
    return this._res;
  }
  public Cond dtor_cond() {
    return this._cond;
  }
}
