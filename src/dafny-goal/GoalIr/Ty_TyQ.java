// Class Ty_TyQ
// Dafny class Ty_TyQ compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Ty_TyQ extends Ty {
  public Unit _u;
  public Ty_TyQ (Unit u) {
    super();
    this._u = u;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Ty_TyQ o = (Ty_TyQ)other;
    return true && java.util.Objects.equals(this._u, o._u);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._u);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Ty.TyQ");
    s.append("(");
    s.append(dafny.Helpers.toString(this._u));
    s.append(")");
    return s.toString();
  }
}
