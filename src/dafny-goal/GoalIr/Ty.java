// Class Ty
// Dafny class Ty compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Ty {
  public Ty() {
  }
  private static final dafny.TypeDescriptor<Ty> _TYPE = dafny.TypeDescriptor.<Ty>referenceWithInitializer(Ty.class, () -> Ty.Default());
  public static dafny.TypeDescriptor<Ty> _typeDescriptor() {
    return (dafny.TypeDescriptor<Ty>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Ty theDefault = Ty.create_TyQ(Unit.Default());
  public static Ty Default() {
    return theDefault;
  }
  public static Ty create_TyQ(Unit u) {
    return new Ty_TyQ(u);
  }
  public static Ty create_TyS() {
    return new Ty_TyS();
  }
  public boolean is_TyQ() { return this instanceof Ty_TyQ; }
  public boolean is_TyS() { return this instanceof Ty_TyS; }
  public Unit dtor_u() {
    Ty d = this;
    return ((Ty_TyQ)d)._u;
  }
}
