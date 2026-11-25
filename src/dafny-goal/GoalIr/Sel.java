// Class Sel
// Dafny class Sel compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Sel {
  public Sel() {
  }
  private static final dafny.TypeDescriptor<Sel> _TYPE = dafny.TypeDescriptor.<Sel>referenceWithInitializer(Sel.class, () -> Sel.Default());
  public static dafny.TypeDescriptor<Sel> _typeDescriptor() {
    return (dafny.TypeDescriptor<Sel>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Sel theDefault = Sel.create_SelGids(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
  public static Sel Default() {
    return theDefault;
  }
  public static Sel create_SelGids(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> gids) {
    return new Sel_SelGids(gids);
  }
  public static Sel create_SelEffect(dafny.DafnySequence<? extends dafny.CodePoint> cls) {
    return new Sel_SelEffect(cls);
  }
  public boolean is_SelGids() { return this instanceof Sel_SelGids; }
  public boolean is_SelEffect() { return this instanceof Sel_SelEffect; }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_gids() {
    Sel d = this;
    return ((Sel_SelGids)d)._gids;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_cls() {
    Sel d = this;
    return ((Sel_SelEffect)d)._cls;
  }
}
