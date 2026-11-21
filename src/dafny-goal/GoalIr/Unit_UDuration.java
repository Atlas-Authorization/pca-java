// Class Unit_UDuration
// Dafny class Unit_UDuration compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Unit_UDuration extends Unit {
  public Unit_UDuration () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Unit_UDuration o = (Unit_UDuration)other;
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
    s.append("GoalIr.Unit.UDuration");
    return s.toString();
  }
}
