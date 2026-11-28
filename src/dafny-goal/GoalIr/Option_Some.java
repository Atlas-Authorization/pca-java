// Class Option_Some<T>
// Dafny class Option_Some<T> compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Option_Some<T> extends Option<T> {
  public T _v;
  public Option_Some (dafny.TypeDescriptor<T> _td_T, T v) {
    super(_td_T);
    this._v = v;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Option_Some<T> o = (Option_Some<T>)other;
    return true && java.util.Objects.equals(this._v, o._v);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._v);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Option.Some");
    s.append("(");
    s.append(dafny.Helpers.toString(this._v));
    s.append(")");
    return s.toString();
  }
}
