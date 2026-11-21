// Class Op_Nin
// Dafny class Op_Nin compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Op_Nin extends Op {
  public Op_Nin () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Op_Nin o = (Op_Nin)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 7;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Op.Nin");
    return s.toString();
  }
}
