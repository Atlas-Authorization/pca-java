// Class LSel
// Dafny class LSel compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class LSel {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _gids;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _verbs;
  public LSel (dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> gids, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs) {
    this._gids = gids;
    this._verbs = verbs;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    LSel o = (LSel)other;
    return true && java.util.Objects.equals(this._gids, o._gids) && java.util.Objects.equals(this._verbs, o._verbs);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._gids);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verbs);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.LSel.LSel");
    s.append("(");
    s.append(dafny.Helpers.toString(this._gids));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._verbs));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<LSel> _TYPE = dafny.TypeDescriptor.<LSel>referenceWithInitializer(LSel.class, () -> LSel.Default());
  public static dafny.TypeDescriptor<LSel> _typeDescriptor() {
    return (dafny.TypeDescriptor<LSel>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final LSel theDefault = LSel.create(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
  public static LSel Default() {
    return theDefault;
  }
  public static LSel create(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> gids, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs) {
    return new LSel(gids, verbs);
  }
  public static LSel create_LSel(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> gids, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs) {
    return create(gids, verbs);
  }
  public boolean is_LSel() { return true; }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_gids() {
    return this._gids;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_verbs() {
    return this._verbs;
  }
}
