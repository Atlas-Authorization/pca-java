// Class OnExceed_OnEscalate
// Dafny class OnExceed_OnEscalate compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class OnExceed_OnEscalate extends OnExceed {
  public OnExceed_OnEscalate () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    OnExceed_OnEscalate o = (OnExceed_OnEscalate)other;
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
    s.append("GoalIr.OnExceed.OnEscalate");
    return s.toString();
  }
}
