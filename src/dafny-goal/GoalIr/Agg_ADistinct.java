// Class Agg_ADistinct
// Dafny class Agg_ADistinct compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Agg_ADistinct extends Agg {
  public Agg_ADistinct () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Agg_ADistinct o = (Agg_ADistinct)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Agg.ADistinct");
    return s.toString();
  }
}
