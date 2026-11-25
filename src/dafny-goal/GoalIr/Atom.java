// Class Atom
// Dafny class Atom compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Atom {
  public Atom() {
  }
  private static final dafny.TypeDescriptor<Atom> _TYPE = dafny.TypeDescriptor.<Atom>referenceWithInitializer(Atom.class, () -> Atom.Default());
  public static dafny.TypeDescriptor<Atom> _typeDescriptor() {
    return (dafny.TypeDescriptor<Atom>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Atom theDefault = Atom.create_AQ(Q.Default());
  public static Atom Default() {
    return theDefault;
  }
  public static Atom create_AQ(Q q) {
    return new Atom_AQ(q);
  }
  public static Atom create_AS(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return new Atom_AS(s);
  }
  public boolean is_AQ() { return this instanceof Atom_AQ; }
  public boolean is_AS() { return this instanceof Atom_AS; }
  public Q dtor_q() {
    Atom d = this;
    return ((Atom_AQ)d)._q;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_s() {
    Atom d = this;
    return ((Atom_AS)d)._s;
  }
}
