// Class Cond_CTrue
// Dafny class Cond_CTrue compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Cond_CTrue extends Cond {
  public Cond_CTrue () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Cond_CTrue o = (Cond_CTrue)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Cond.CTrue");
    return s.toString();
  }
}
