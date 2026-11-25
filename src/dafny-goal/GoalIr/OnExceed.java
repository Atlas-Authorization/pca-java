// Class OnExceed
// Dafny class OnExceed compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class OnExceed {
  public OnExceed() {
  }
  private static final dafny.TypeDescriptor<OnExceed> _TYPE = dafny.TypeDescriptor.<OnExceed>referenceWithInitializer(OnExceed.class, () -> OnExceed.Default());
  public static dafny.TypeDescriptor<OnExceed> _typeDescriptor() {
    return (dafny.TypeDescriptor<OnExceed>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final OnExceed theDefault = OnExceed.create_OnDeny();
  public static OnExceed Default() {
    return theDefault;
  }
  public static OnExceed create_OnDeny() {
    return new OnExceed_OnDeny();
  }
  public static OnExceed create_OnEscalate() {
    return new OnExceed_OnEscalate();
  }
  public boolean is_OnDeny() { return this instanceof OnExceed_OnDeny; }
  public boolean is_OnEscalate() { return this instanceof OnExceed_OnEscalate; }
  public static java.util.ArrayList<OnExceed> AllSingletonConstructors() {
    java.util.ArrayList<OnExceed> singleton_iterator = new java.util.ArrayList<>();
    singleton_iterator.add(new OnExceed_OnDeny());
    singleton_iterator.add(new OnExceed_OnEscalate());
    return singleton_iterator;
  }
}
