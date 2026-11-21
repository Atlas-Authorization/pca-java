// Class Term
// Dafny class Term compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Term {
  public Term() {
  }
  private static final dafny.TypeDescriptor<Term> _TYPE = dafny.TypeDescriptor.<Term>referenceWithInitializer(Term.class, () -> Term.Default());
  public static dafny.TypeDescriptor<Term> _typeDescriptor() {
    return (dafny.TypeDescriptor<Term>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Term theDefault = Term.create_Param(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), Ty.Default());
  public static Term Default() {
    return theDefault;
  }
  public static Term create_Param(dafny.DafnySequence<? extends dafny.CodePoint> path, Ty ty) {
    return new Term_Param(path, ty);
  }
  public static Term create_Lit(V v) {
    return new Term_Lit(v);
  }
  public static Term create_HistAgg(dafny.DafnySequence<? extends dafny.CodePoint> bid, Unit u) {
    return new Term_HistAgg(bid, u);
  }
  public boolean is_Param() { return this instanceof Term_Param; }
  public boolean is_Lit() { return this instanceof Term_Lit; }
  public boolean is_HistAgg() { return this instanceof Term_HistAgg; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_path() {
    Term d = this;
    return ((Term_Param)d)._path;
  }
  public Ty dtor_ty() {
    Term d = this;
    return ((Term_Param)d)._ty;
  }
  public V dtor_v() {
    Term d = this;
    return ((Term_Lit)d)._v;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_bid() {
    Term d = this;
    return ((Term_HistAgg)d)._bid;
  }
  public Unit dtor_u() {
    Term d = this;
    return ((Term_HistAgg)d)._u;
  }
}
