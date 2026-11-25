// Class Scope_SPrincipal
// Dafny class Scope_SPrincipal compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Scope_SPrincipal extends Scope {
  public Scope_SPrincipal () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Scope_SPrincipal o = (Scope_SPrincipal)other;
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
    s.append("GoalIr.Scope.SPrincipal");
    return s.toString();
  }
}
