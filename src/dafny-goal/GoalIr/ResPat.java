// Class ResPat
// Dafny class ResPat compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class ResPat {
  public ResPat() {
  }
  private static final dafny.TypeDescriptor<ResPat> _TYPE = dafny.TypeDescriptor.<ResPat>referenceWithInitializer(ResPat.class, () -> ResPat.Default());
  public static dafny.TypeDescriptor<ResPat> _typeDescriptor() {
    return (dafny.TypeDescriptor<ResPat>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final ResPat theDefault = ResPat.create_PStar();
  public static ResPat Default() {
    return theDefault;
  }
  public static ResPat create_PStar() {
    return new ResPat_PStar();
  }
  public static ResPat create_PSet(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> ids) {
    return new ResPat_PSet(ids);
  }
  public boolean is_PStar() { return this instanceof ResPat_PStar; }
  public boolean is_PSet() { return this instanceof ResPat_PSet; }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_ids() {
    ResPat d = this;
    return ((ResPat_PSet)d)._ids;
  }
}
