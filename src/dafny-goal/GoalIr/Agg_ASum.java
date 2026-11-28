// Class Agg_ASum
// Dafny class Agg_ASum compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Agg_ASum extends Agg {
  public Agg_ASum () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Agg_ASum o = (Agg_ASum)other;
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
    s.append("GoalIr.Agg.ASum");
    return s.toString();
  }
}
