// Class RelDecl
// Dafny class RelDecl compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class RelDecl {
  public dafny.DafnySequence<? extends dafny.CodePoint> _rel;
  public dafny.DafnySequence<? extends dafny.CodePoint> _anchor;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _members;
  public RelDecl (dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> members) {
    this._rel = rel;
    this._anchor = anchor;
    this._members = members;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    RelDecl o = (RelDecl)other;
    return true && java.util.Objects.equals(this._rel, o._rel) && java.util.Objects.equals(this._anchor, o._anchor) && java.util.Objects.equals(this._members, o._members);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._rel);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._anchor);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._members);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.RelDecl.RelDecl");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._rel));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._anchor));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._members));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<RelDecl> _TYPE = dafny.TypeDescriptor.<RelDecl>referenceWithInitializer(RelDecl.class, () -> RelDecl.Default());
  public static dafny.TypeDescriptor<RelDecl> _typeDescriptor() {
    return (dafny.TypeDescriptor<RelDecl>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final RelDecl theDefault = RelDecl.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
  public static RelDecl Default() {
    return theDefault;
  }
  public static RelDecl create(dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> members) {
    return new RelDecl(rel, anchor, members);
  }
  public static RelDecl create_RelDecl(dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> members) {
    return create(rel, anchor, members);
  }
  public boolean is_RelDecl() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_rel() {
    return this._rel;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_anchor() {
    return this._anchor;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_members() {
    return this._members;
  }
}
