// Class ParamDecl
// Dafny class ParamDecl compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ParamDecl {
  public dafny.DafnySequence<? extends dafny.CodePoint> _path;
  public Ty _ty;
  public ParamDecl (dafny.DafnySequence<? extends dafny.CodePoint> path, Ty ty) {
    this._path = path;
    this._ty = ty;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ParamDecl o = (ParamDecl)other;
    return true && java.util.Objects.equals(this._path, o._path) && java.util.Objects.equals(this._ty, o._ty);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._path);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ty);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ParamDecl.ParamDecl");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._path));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._ty));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<ParamDecl> _TYPE = dafny.TypeDescriptor.<ParamDecl>referenceWithInitializer(ParamDecl.class, () -> ParamDecl.Default());
  public static dafny.TypeDescriptor<ParamDecl> _typeDescriptor() {
    return (dafny.TypeDescriptor<ParamDecl>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final ParamDecl theDefault = ParamDecl.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), Ty.Default());
  public static ParamDecl Default() {
    return theDefault;
  }
  public static ParamDecl create(dafny.DafnySequence<? extends dafny.CodePoint> path, Ty ty) {
    return new ParamDecl(path, ty);
  }
  public static ParamDecl create_ParamDecl(dafny.DafnySequence<? extends dafny.CodePoint> path, Ty ty) {
    return create(path, ty);
  }
  public boolean is_ParamDecl() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_path() {
    return this._path;
  }
  public Ty dtor_ty() {
    return this._ty;
  }
}
