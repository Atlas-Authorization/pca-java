// Class Cond_And
// Dafny class Cond_And compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Cond_And extends Cond {
  public Cond _a;
  public Cond _b;
  public Cond_And (Cond a, Cond b) {
    super();
    this._a = a;
    this._b = b;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Cond_And o = (Cond_And)other;
    return true && java.util.Objects.equals(this._a, o._a) && java.util.Objects.equals(this._b, o._b);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._a);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._b);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Cond.And");
    s.append("(");
    s.append(dafny.Helpers.toString(this._a));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._b));
    s.append(")");
    return s.toString();
  }
}
