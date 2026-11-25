// Class BCore
// Dafny class BCore compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class BCore {
  public Agg _agg;
  public Term _value;
  public dafny.DafnySequence<? extends dafny.CodePoint> _key;
  public Window _window;
  public Scope _scope;
  public Q _cap;
  public OnExceed _onExceed;
  public BCore (Agg agg, Term value, dafny.DafnySequence<? extends dafny.CodePoint> key, Window window, Scope scope, Q cap, OnExceed onExceed) {
    this._agg = agg;
    this._value = value;
    this._key = key;
    this._window = window;
    this._scope = scope;
    this._cap = cap;
    this._onExceed = onExceed;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    BCore o = (BCore)other;
    return true && java.util.Objects.equals(this._agg, o._agg) && java.util.Objects.equals(this._value, o._value) && java.util.Objects.equals(this._key, o._key) && java.util.Objects.equals(this._window, o._window) && java.util.Objects.equals(this._scope, o._scope) && java.util.Objects.equals(this._cap, o._cap) && java.util.Objects.equals(this._onExceed, o._onExceed);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._agg);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._value);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._key);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._window);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._scope);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._cap);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._onExceed);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.BCore.BCore");
    s.append("(");
    s.append(dafny.Helpers.toString(this._agg));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._value));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._key));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._window));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._scope));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._cap));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._onExceed));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<BCore> _TYPE = dafny.TypeDescriptor.<BCore>referenceWithInitializer(BCore.class, () -> BCore.Default());
  public static dafny.TypeDescriptor<BCore> _typeDescriptor() {
    return (dafny.TypeDescriptor<BCore>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final BCore theDefault = BCore.create(Agg.Default(), Term.Default(), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), Window.Default(), Scope.Default(), Q.Default(), OnExceed.Default());
  public static BCore Default() {
    return theDefault;
  }
  public static BCore create(Agg agg, Term value, dafny.DafnySequence<? extends dafny.CodePoint> key, Window window, Scope scope, Q cap, OnExceed onExceed) {
    return new BCore(agg, value, key, window, scope, cap, onExceed);
  }
  public static BCore create_BCore(Agg agg, Term value, dafny.DafnySequence<? extends dafny.CodePoint> key, Window window, Scope scope, Q cap, OnExceed onExceed) {
    return create(agg, value, key, window, scope, cap, onExceed);
  }
  public boolean is_BCore() { return true; }
  public Agg dtor_agg() {
    return this._agg;
  }
  public Term dtor_value() {
    return this._value;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_key() {
    return this._key;
  }
  public Window dtor_window() {
    return this._window;
  }
  public Scope dtor_scope() {
    return this._scope;
  }
  public Q dtor_cap() {
    return this._cap;
  }
  public OnExceed dtor_onExceed() {
    return this._onExceed;
  }
}
