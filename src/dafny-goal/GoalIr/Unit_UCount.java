// Class Unit_UCount
// Dafny class Unit_UCount compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Unit_UCount extends Unit {
  public Unit_UCount () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Unit_UCount o = (Unit_UCount)other;
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
    s.append("GoalIr.Unit.UCount");
    return s.toString();
  }
}
