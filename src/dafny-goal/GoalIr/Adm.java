// Class Adm
// Dafny class Adm compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Adm {
  public dafny.DafnySequence<? extends dafny.CodePoint> _gid;
  public Act _act;
  public Adm (dafny.DafnySequence<? extends dafny.CodePoint> gid, Act act) {
    this._gid = gid;
    this._act = act;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Adm o = (Adm)other;
    return true && java.util.Objects.equals(this._gid, o._gid) && java.util.Objects.equals(this._act, o._act);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._gid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._act);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Adm.Adm");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._gid));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._act));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Adm> _TYPE = dafny.TypeDescriptor.<Adm>referenceWithInitializer(Adm.class, () -> Adm.Default());
  public static dafny.TypeDescriptor<Adm> _typeDescriptor() {
    return (dafny.TypeDescriptor<Adm>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Adm theDefault = Adm.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), Act.Default());
  public static Adm Default() {
    return theDefault;
  }
  public static Adm create(dafny.DafnySequence<? extends dafny.CodePoint> gid, Act act) {
    return new Adm(gid, act);
  }
  public static Adm create_Adm(dafny.DafnySequence<? extends dafny.CodePoint> gid, Act act) {
    return create(gid, act);
  }
  public boolean is_Adm() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_gid() {
    return this._gid;
  }
  public Act dtor_act() {
    return this._act;
  }
}
