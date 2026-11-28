// Class PR_Ok<T>
// Dafny class PR_Ok<T> compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public class PR_Ok<T> extends PR<T> {
  public T _v;
  public dafny.DafnySequence<? extends Tok> _rest;
  public PR_Ok (dafny.TypeDescriptor<T> _td_T, T v, dafny.DafnySequence<? extends Tok> rest) {
    super(_td_T);
    this._v = v;
    this._rest = rest;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    PR_Ok<T> o = (PR_Ok<T>)other;
    return true && java.util.Objects.equals(this._v, o._v) && java.util.Objects.equals(this._rest, o._rest);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._v);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._rest);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalRender.PR.Ok");
    s.append("(");
    s.append(dafny.Helpers.toString(this._v));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._rest));
    s.append(")");
    return s.toString();
  }
}
