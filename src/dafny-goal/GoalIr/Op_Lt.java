// Class Op_Lt
// Dafny class Op_Lt compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Op_Lt extends Op {
  public Op_Lt () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Op_Lt o = (Op_Lt)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Op.Lt");
    return s.toString();
  }
}
