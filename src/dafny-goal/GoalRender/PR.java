// Class PR<T>
// Dafny class PR<T> compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class PR<T> {
  protected dafny.TypeDescriptor<T> _td_T;
  public PR(dafny.TypeDescriptor<T> _td_T) {
    this._td_T = _td_T;
  }
  public static <T> dafny.TypeDescriptor<PR<T>> _typeDescriptor(dafny.TypeDescriptor<T> _td_T) {
    return (dafny.TypeDescriptor<PR<T>>) (dafny.TypeDescriptor<?>) dafny.TypeDescriptor.<PR<T>>referenceWithInitializer(PR.class, () -> PR.<T>Default(_td_T));
  }

  public static <T> PR<T> Default(dafny.TypeDescriptor<T> _td_T) {
    return PR.<T>create_Fail(_td_T);
  }
  public static <T> PR<T> create_Fail(dafny.TypeDescriptor<T> _td_T) {
    return new PR_Fail<T>(_td_T);
  }
  public static <T> PR<T> create_Ok(dafny.TypeDescriptor<T> _td_T, T v, dafny.DafnySequence<? extends Tok> rest) {
    return new PR_Ok<T>(_td_T, v, rest);
  }
  public boolean is_Fail() { return this instanceof PR_Fail; }
  public boolean is_Ok() { return this instanceof PR_Ok; }
  public T dtor_v() {
    PR<T> d = this;
    return ((PR_Ok<T>)d)._v;
  }
  public dafny.DafnySequence<? extends Tok> dtor_rest() {
    PR<T> d = this;
    return ((PR_Ok<T>)d)._rest;
  }
}
