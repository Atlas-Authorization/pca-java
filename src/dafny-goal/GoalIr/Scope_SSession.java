// Class Scope_SSession
// Dafny class Scope_SSession compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Scope_SSession extends Scope {
  public Scope_SSession () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Scope_SSession o = (Scope_SSession)other;
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
    s.append("GoalIr.Scope.SSession");
    return s.toString();
  }
}
