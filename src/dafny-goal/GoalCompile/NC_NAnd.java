// Class NC_NAnd
// Dafny class NC_NAnd compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class NC_NAnd extends NC {
  public NC _a;
  public NC _b;
  public NC_NAnd (NC a, NC b) {
    super();
    this._a = a;
    this._b = b;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    NC_NAnd o = (NC_NAnd)other;
    return true && java.util.Objects.equals(this._a, o._a) && java.util.Objects.equals(this._b, o._b);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._a);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._b);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalCompile.NC.NAnd");
    s.append("(");
    s.append(dafny.Helpers.toString(this._a));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._b));
    s.append(")");
    return s.toString();
  }
}
