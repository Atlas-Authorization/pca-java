// Class NC_NAtom
// Dafny class NC_NAtom compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class NC_NAtom extends NC {
  public GoalIr.Op _op;
  public GoalIr.Term _l;
  public GoalIr.Term _r;
  public NC_NAtom (GoalIr.Op op, GoalIr.Term l, GoalIr.Term r) {
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
    NC_NAtom o = (NC_NAtom)other;
    return true && java.util.Objects.equals(this._op, o._op) && java.util.Objects.equals(this._l, o._l) && java.util.Objects.equals(this._r, o._r);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._op);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._l);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._r);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalCompile.NC.NAtom");
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
