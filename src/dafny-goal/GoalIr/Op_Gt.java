// Class Op_Gt
// Dafny class Op_Gt compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Op_Gt extends Op {
  public Op_Gt () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Op_Gt o = (Op_Gt)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Op.Gt");
    return s.toString();
  }
}
