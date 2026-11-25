// Class VerbDecl
// Dafny class VerbDecl compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class VerbDecl {
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public dafny.DafnySequence<? extends dafny.CodePoint> _cls;
  public dafny.DafnySequence<? extends ParamDecl> _params;
  public VerbDecl (dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> cls, dafny.DafnySequence<? extends ParamDecl> params) {
    this._verb = verb;
    this._cls = cls;
    this._params = params;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    VerbDecl o = (VerbDecl)other;
    return true && java.util.Objects.equals(this._verb, o._verb) && java.util.Objects.equals(this._cls, o._cls) && java.util.Objects.equals(this._params, o._params);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verb);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._cls);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._params);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.VerbDecl.VerbDecl");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._verb));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._cls));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._params));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<VerbDecl> _TYPE = dafny.TypeDescriptor.<VerbDecl>referenceWithInitializer(VerbDecl.class, () -> VerbDecl.Default());
  public static dafny.TypeDescriptor<VerbDecl> _typeDescriptor() {
    return (dafny.TypeDescriptor<VerbDecl>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final VerbDecl theDefault = VerbDecl.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<ParamDecl> empty(ParamDecl._typeDescriptor()));
  public static VerbDecl Default() {
    return theDefault;
  }
  public static VerbDecl create(dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> cls, dafny.DafnySequence<? extends ParamDecl> params) {
    return new VerbDecl(verb, cls, params);
  }
  public static VerbDecl create_VerbDecl(dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> cls, dafny.DafnySequence<? extends ParamDecl> params) {
    return create(verb, cls, params);
  }
  public boolean is_VerbDecl() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    return this._verb;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_cls() {
    return this._cls;
  }
  public dafny.DafnySequence<? extends ParamDecl> dtor_params() {
    return this._params;
  }
}
