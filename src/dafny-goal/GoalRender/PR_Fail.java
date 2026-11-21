// Class PR_Fail<T>
// Dafny class PR_Fail<T> compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public class PR_Fail<T> extends PR<T> {
  public PR_Fail (dafny.TypeDescriptor<T> _td_T) {
    super(_td_T);
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    PR_Fail<T> o = (PR_Fail<T>)other;
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
    s.append("GoalRender.PR.Fail");
    return s.toString();
  }
}
