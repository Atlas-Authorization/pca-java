// Class Agg
// Dafny class Agg compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Agg {
  public Agg() {
  }
  private static final dafny.TypeDescriptor<Agg> _TYPE = dafny.TypeDescriptor.<Agg>referenceWithInitializer(Agg.class, () -> Agg.Default());
  public static dafny.TypeDescriptor<Agg> _typeDescriptor() {
    return (dafny.TypeDescriptor<Agg>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Agg theDefault = Agg.create_ACount();
  public static Agg Default() {
    return theDefault;
  }
  public static Agg create_ACount() {
    return new Agg_ACount();
  }
  public static Agg create_ASum() {
    return new Agg_ASum();
  }
  public static Agg create_AMax() {
    return new Agg_AMax();
  }
  public static Agg create_ADistinct() {
    return new Agg_ADistinct();
  }
  public boolean is_ACount() { return this instanceof Agg_ACount; }
  public boolean is_ASum() { return this instanceof Agg_ASum; }
  public boolean is_AMax() { return this instanceof Agg_AMax; }
  public boolean is_ADistinct() { return this instanceof Agg_ADistinct; }
  public static java.util.ArrayList<Agg> AllSingletonConstructors() {
    java.util.ArrayList<Agg> singleton_iterator = new java.util.ArrayList<>();
    singleton_iterator.add(new Agg_ACount());
    singleton_iterator.add(new Agg_ASum());
    singleton_iterator.add(new Agg_AMax());
    singleton_iterator.add(new Agg_ADistinct());
    return singleton_iterator;
  }
}
