// Class OnExceed_OnDeny
// Dafny class OnExceed_OnDeny compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class OnExceed_OnDeny extends OnExceed {
  public OnExceed_OnDeny () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    OnExceed_OnDeny o = (OnExceed_OnDeny)other;
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
    s.append("GoalIr.OnExceed.OnDeny");
    return s.toString();
  }
}
