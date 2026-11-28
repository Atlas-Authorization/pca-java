// Class Scope
// Dafny class Scope compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Scope {
  public Scope() {
  }
  private static final dafny.TypeDescriptor<Scope> _TYPE = dafny.TypeDescriptor.<Scope>referenceWithInitializer(Scope.class, () -> Scope.Default());
  public static dafny.TypeDescriptor<Scope> _typeDescriptor() {
    return (dafny.TypeDescriptor<Scope>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Scope theDefault = Scope.create_SSession();
  public static Scope Default() {
    return theDefault;
  }
  public static Scope create_SSession() {
    return new Scope_SSession();
  }
  public static Scope create_SPrincipal() {
    return new Scope_SPrincipal();
  }
  public static Scope create_SOrg() {
    return new Scope_SOrg();
  }
  public static Scope create_SFleet(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> agents) {
    return new Scope_SFleet(agents);
  }
  public boolean is_SSession() { return this instanceof Scope_SSession; }
  public boolean is_SPrincipal() { return this instanceof Scope_SPrincipal; }
  public boolean is_SOrg() { return this instanceof Scope_SOrg; }
  public boolean is_SFleet() { return this instanceof Scope_SFleet; }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_agents() {
    Scope d = this;
    return ((Scope_SFleet)d)._agents;
  }
}
