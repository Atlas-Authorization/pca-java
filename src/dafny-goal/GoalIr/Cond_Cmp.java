// Class Cond_Cmp
// Dafny class Cond_Cmp compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Cond_Cmp extends Cond {
  public Op _op;
  public Term _l;
  public Term _r;
  public Cond_Cmp (Op op, Term l, Term r) {
    super();
    this._op = op;
    this._l = l;
    this._r = r;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Cond_Cmp o = (Cond_Cmp)other;
    return true && java.util.Objects.equals(this._op, o._op) && java.util.Objects.equals(this._l, o._l) && java.util.Objects.equals(this._r, o._r);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._op);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._l);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._r);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Cond.Cmp");
    s.append("(");
    s.append(dafny.Helpers.toString(this._op));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._l));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._r));
    s.append(")");
    return s.toString();
  }
}
