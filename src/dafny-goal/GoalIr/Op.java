// Class Op
// Dafny class Op compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Op {
  public Op() {
  }
  private static final dafny.TypeDescriptor<Op> _TYPE = dafny.TypeDescriptor.<Op>referenceWithInitializer(Op.class, () -> Op.Default());
  public static dafny.TypeDescriptor<Op> _typeDescriptor() {
    return (dafny.TypeDescriptor<Op>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Op theDefault = Op.create_Eq();
  public static Op Default() {
    return theDefault;
  }
  public static Op create_Eq() {
    return new Op_Eq();
  }
  public static Op create_Ne() {
    return new Op_Ne();
  }
  public static Op create_Lt() {
    return new Op_Lt();
  }
  public static Op create_Lte() {
    return new Op_Lte();
  }
  public static Op create_Gt() {
    return new Op_Gt();
  }
  public static Op create_Gte() {
    return new Op_Gte();
  }
  public static Op create_In() {
    return new Op_In();
  }
  public static Op create_Nin() {
    return new Op_Nin();
  }
  public boolean is_Eq() { return this instanceof Op_Eq; }
  public boolean is_Ne() { return this instanceof Op_Ne; }
  public boolean is_Lt() { return this instanceof Op_Lt; }
  public boolean is_Lte() { return this instanceof Op_Lte; }
  public boolean is_Gt() { return this instanceof Op_Gt; }
  public boolean is_Gte() { return this instanceof Op_Gte; }
  public boolean is_In() { return this instanceof Op_In; }
  public boolean is_Nin() { return this instanceof Op_Nin; }
  public static java.util.ArrayList<Op> AllSingletonConstructors() {
    java.util.ArrayList<Op> singleton_iterator = new java.util.ArrayList<>();
    singleton_iterator.add(new Op_Eq());
    singleton_iterator.add(new Op_Ne());
    singleton_iterator.add(new Op_Lt());
    singleton_iterator.add(new Op_Lte());
    singleton_iterator.add(new Op_Gt());
    singleton_iterator.add(new Op_Gte());
    singleton_iterator.add(new Op_In());
    singleton_iterator.add(new Op_Nin());
    return singleton_iterator;
  }
}
