// Class Unit_UBytes
// Dafny class Unit_UBytes compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Unit_UBytes extends Unit {
  public Unit_UBytes () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Unit_UBytes o = (Unit_UBytes)other;
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
    s.append("GoalIr.Unit.UBytes");
    return s.toString();
  }
}
