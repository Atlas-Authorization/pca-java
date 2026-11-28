// Class NC
// Dafny class NC compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class NC {
  public NC() {
  }
  private static final dafny.TypeDescriptor<NC> _TYPE = dafny.TypeDescriptor.<NC>referenceWithInitializer(NC.class, () -> NC.Default());
  public static dafny.TypeDescriptor<NC> _typeDescriptor() {
    return (dafny.TypeDescriptor<NC>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final NC theDefault = NC.create_NTrue();
  public static NC Default() {
    return theDefault;
  }
  public static NC create_NTrue() {
    return new NC_NTrue();
  }
  public static NC create_NFalse() {
    return new NC_NFalse();
  }
  public static NC create_NAtom(GoalIr.Op op, GoalIr.Term l, GoalIr.Term r) {
    return new NC_NAtom(op, l, r);
  }
  public static NC create_NAnd(NC a, NC b) {
    return new NC_NAnd(a, b);
  }
  public static NC create_NOr(NC a, NC b) {
    return new NC_NOr(a, b);
  }
  public boolean is_NTrue() { return this instanceof NC_NTrue; }
  public boolean is_NFalse() { return this instanceof NC_NFalse; }
  public boolean is_NAtom() { return this instanceof NC_NAtom; }
  public boolean is_NAnd() { return this instanceof NC_NAnd; }
  public boolean is_NOr() { return this instanceof NC_NOr; }
  public GoalIr.Op dtor_op() {
    NC d = this;
    return ((NC_NAtom)d)._op;
  }
  public GoalIr.Term dtor_l() {
    NC d = this;
    return ((NC_NAtom)d)._l;
  }
  public GoalIr.Term dtor_r() {
    NC d = this;
    return ((NC_NAtom)d)._r;
  }
  public NC dtor_a() {
    NC d = this;
    if (d instanceof NC_NAnd) { return ((NC_NAnd)d)._a; }
    return ((NC_NOr)d)._a;
  }
  public NC dtor_b() {
    NC d = this;
    if (d instanceof NC_NAnd) { return ((NC_NAnd)d)._b; }
    return ((NC_NOr)d)._b;
  }
}
