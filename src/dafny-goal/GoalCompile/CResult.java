// Class CResult
// Dafny class CResult compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class CResult {
  public CResult() {
  }
  private static final dafny.TypeDescriptor<CResult> _TYPE = dafny.TypeDescriptor.<CResult>referenceWithInitializer(CResult.class, () -> CResult.Default());
  public static dafny.TypeDescriptor<CResult> _typeDescriptor() {
    return (dafny.TypeDescriptor<CResult>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final CResult theDefault = CResult.create_Compiled(Pol.Default());
  public static CResult Default() {
    return theDefault;
  }
  public static CResult create_Compiled(Pol p) {
    return new CResult_Compiled(p);
  }
  public static CResult create_CEscalate(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> reasons) {
    return new CResult_CEscalate(reasons);
  }
  public boolean is_Compiled() { return this instanceof CResult_Compiled; }
  public boolean is_CEscalate() { return this instanceof CResult_CEscalate; }
  public Pol dtor_p() {
    CResult d = this;
    return ((CResult_Compiled)d)._p;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_reasons() {
    CResult d = this;
    return ((CResult_CEscalate)d)._reasons;
  }
}
