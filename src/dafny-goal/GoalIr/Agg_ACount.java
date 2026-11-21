// Class Agg_ACount
// Dafny class Agg_ACount compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Agg_ACount extends Agg {
  public Agg_ACount () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Agg_ACount o = (Agg_ACount)other;
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
    s.append("GoalIr.Agg.ACount");
    return s.toString();
  }
}
