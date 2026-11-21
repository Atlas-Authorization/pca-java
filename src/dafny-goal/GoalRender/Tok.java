// Class Tok
// Dafny class Tok compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Tok {
  public Tok() {
  }
  private static final dafny.TypeDescriptor<Tok> _TYPE = dafny.TypeDescriptor.<Tok>referenceWithInitializer(Tok.class, () -> Tok.Default());
  public static dafny.TypeDescriptor<Tok> _typeDescriptor() {
    return (dafny.TypeDescriptor<Tok>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Tok theDefault = Tok.create_TKw(java.math.BigInteger.ZERO);
  public static Tok Default() {
    return theDefault;
  }
  public static Tok create_TKw(java.math.BigInteger k) {
    return new Tok_TKw(k);
  }
  public static Tok create_TI(java.math.BigInteger i) {
    return new Tok_TI(i);
  }
  public static Tok create_TS(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return new Tok_TS(s);
  }
  public boolean is_TKw() { return this instanceof Tok_TKw; }
  public boolean is_TI() { return this instanceof Tok_TI; }
  public boolean is_TS() { return this instanceof Tok_TS; }
  public java.math.BigInteger dtor_k() {
    Tok d = this;
    return ((Tok_TKw)d)._k;
  }
  public java.math.BigInteger dtor_i() {
    Tok d = this;
    return ((Tok_TI)d)._i;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_s() {
    Tok d = this;
    return ((Tok_TS)d)._s;
  }
}
