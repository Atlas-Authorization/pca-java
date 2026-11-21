// Class Term_Lit
// Dafny class Term_Lit compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Term_Lit extends Term {
  public V _v;
  public Term_Lit (V v) {
    super();
    this._v = v;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Term_Lit o = (Term_Lit)other;
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
    s.append("GoalIr.Term.Lit");
    s.append("(");
    s.append(dafny.Helpers.toString(this._v));
    s.append(")");
    return s.toString();
  }
}
