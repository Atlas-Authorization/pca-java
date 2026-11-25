// Class Unit_URatio
// Dafny class Unit_URatio compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Unit_URatio extends Unit {
  public Unit_URatio () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Unit_URatio o = (Unit_URatio)other;
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
    s.append("GoalIr.Unit.URatio");
    return s.toString();
  }
}
