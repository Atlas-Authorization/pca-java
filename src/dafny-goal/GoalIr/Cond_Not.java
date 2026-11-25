// Class Cond_Not
// Dafny class Cond_Not compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Cond_Not extends Cond {
  public Cond _c;
  public Cond_Not (Cond c) {
    super();
    this._c = c;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Cond_Not o = (Cond_Not)other;
    return true && java.util.Objects.equals(this._c, o._c);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._c);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Cond.Not");
    s.append("(");
    s.append(dafny.Helpers.toString(this._c));
    s.append(")");
    return s.toString();
  }
}
