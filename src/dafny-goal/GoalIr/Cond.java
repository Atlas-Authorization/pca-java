// Class Cond
// Dafny class Cond compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Cond {
  public Cond() {
  }
  private static final dafny.TypeDescriptor<Cond> _TYPE = dafny.TypeDescriptor.<Cond>referenceWithInitializer(Cond.class, () -> Cond.Default());
  public static dafny.TypeDescriptor<Cond> _typeDescriptor() {
    return (dafny.TypeDescriptor<Cond>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Cond theDefault = Cond.create_CTrue();
  public static Cond Default() {
    return theDefault;
  }
  public static Cond create_CTrue() {
    return new Cond_CTrue();
  }
  public static Cond create_Cmp(Op op, Term l, Term r) {
    return new Cond_Cmp(op, l, r);
  }
  public static Cond create_And(Cond a, Cond b) {
    return new Cond_And(a, b);
  }
  public static Cond create_Or(Cond a, Cond b) {
    return new Cond_Or(a, b);
  }
  public static Cond create_Not(Cond c) {
    return new Cond_Not(c);
  }
  public boolean is_CTrue() { return this instanceof Cond_CTrue; }
  public boolean is_Cmp() { return this instanceof Cond_Cmp; }
  public boolean is_And() { return this instanceof Cond_And; }
  public boolean is_Or() { return this instanceof Cond_Or; }
  public boolean is_Not() { return this instanceof Cond_Not; }
  public Op dtor_op() {
    Cond d = this;
    return ((Cond_Cmp)d)._op;
  }
  public Term dtor_l() {
    Cond d = this;
    return ((Cond_Cmp)d)._l;
  }
  public Term dtor_r() {
    Cond d = this;
    return ((Cond_Cmp)d)._r;
  }
  public Cond dtor_a() {
    Cond d = this;
    if (d instanceof Cond_And) { return ((Cond_And)d)._a; }
    return ((Cond_Or)d)._a;
  }
  public Cond dtor_b() {
    Cond d = this;
    if (d instanceof Cond_And) { return ((Cond_And)d)._b; }
    return ((Cond_Or)d)._b;
  }
  public Cond dtor_c() {
    Cond d = this;
    return ((Cond_Not)d)._c;
  }
}
