// Class Agg_AMax
// Dafny class Agg_AMax compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Agg_AMax extends Agg {
  public Agg_AMax () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Agg_AMax o = (Agg_AMax)other;
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
    s.append("GoalIr.Agg.AMax");
    return s.toString();
  }
}
