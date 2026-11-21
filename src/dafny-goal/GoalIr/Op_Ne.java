// Class Op_Ne
// Dafny class Op_Ne compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Op_Ne extends Op {
  public Op_Ne () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Op_Ne o = (Op_Ne)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Op.Ne");
    return s.toString();
  }
}
