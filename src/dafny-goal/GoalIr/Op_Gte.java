// Class Op_Gte
// Dafny class Op_Gte compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Op_Gte extends Op {
  public Op_Gte () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Op_Gte o = (Op_Gte)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 5;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Op.Gte");
    return s.toString();
  }
}
