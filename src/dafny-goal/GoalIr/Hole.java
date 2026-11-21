// Class Hole
// Dafny class Hole compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Hole {
  public dafny.DafnySequence<? extends dafny.CodePoint> _hid;
  public dafny.DafnySequence<? extends dafny.CodePoint> _q;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _domain;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _affects;
  public boolean _global;
  public Hole (dafny.DafnySequence<? extends dafny.CodePoint> hid, dafny.DafnySequence<? extends dafny.CodePoint> q, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> domain, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> affects, boolean global) {
    this._hid = hid;
    this._q = q;
    this._domain = domain;
    this._affects = affects;
    this._global = global;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Hole o = (Hole)other;
    return true && java.util.Objects.equals(this._hid, o._hid) && java.util.Objects.equals(this._q, o._q) && java.util.Objects.equals(this._domain, o._domain) && java.util.Objects.equals(this._affects, o._affects) && this._global == o._global;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._hid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._q);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._domain);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._affects);
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._global);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Hole.Hole");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._hid));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._q));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._domain));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._affects));
    s.append(", ");
    s.append(this._global);
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Hole> _TYPE = dafny.TypeDescriptor.<Hole>referenceWithInitializer(Hole.class, () -> Hole.Default());
  public static dafny.TypeDescriptor<Hole> _typeDescriptor() {
    return (dafny.TypeDescriptor<Hole>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Hole theDefault = Hole.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), false);
  public static Hole Default() {
    return theDefault;
  }
  public static Hole create(dafny.DafnySequence<? extends dafny.CodePoint> hid, dafny.DafnySequence<? extends dafny.CodePoint> q, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> domain, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> affects, boolean global) {
    return new Hole(hid, q, domain, affects, global);
  }
  public static Hole create_Hole(dafny.DafnySequence<? extends dafny.CodePoint> hid, dafny.DafnySequence<? extends dafny.CodePoint> q, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> domain, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> affects, boolean global) {
    return create(hid, q, domain, affects, global);
  }
  public boolean is_Hole() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_hid() {
    return this._hid;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_q() {
    return this._q;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_domain() {
    return this._domain;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_affects() {
    return this._affects;
  }
  public boolean dtor_global() {
    return this._global;
  }
}
