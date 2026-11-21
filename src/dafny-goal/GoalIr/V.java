// Class V
// Dafny class V compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class V {
  public V() {
  }
  private static final dafny.TypeDescriptor<V> _TYPE = dafny.TypeDescriptor.<V>referenceWithInitializer(V.class, () -> V.Default());
  public static dafny.TypeDescriptor<V> _typeDescriptor() {
    return (dafny.TypeDescriptor<V>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final V theDefault = V.create_VQ(Q.Default());
  public static V Default() {
    return theDefault;
  }
  public static V create_VQ(Q q) {
    return new V_VQ(q);
  }
  public static V create_VS(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return new V_VS(s);
  }
  public static V create_VSet(dafny.DafnySequence<? extends Atom> items) {
    return new V_VSet(items);
  }
  public boolean is_VQ() { return this instanceof V_VQ; }
  public boolean is_VS() { return this instanceof V_VS; }
  public boolean is_VSet() { return this instanceof V_VSet; }
  public Q dtor_q() {
    V d = this;
    return ((V_VQ)d)._q;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_s() {
    V d = this;
    return ((V_VS)d)._s;
  }
  public dafny.DafnySequence<? extends Atom> dtor_items() {
    V d = this;
    return ((V_VSet)d)._items;
  }
}
