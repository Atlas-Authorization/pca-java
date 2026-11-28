// Class Scope_SOrg
// Dafny class Scope_SOrg compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Scope_SOrg extends Scope {
  public Scope_SOrg () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Scope_SOrg o = (Scope_SOrg)other;
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
    s.append("GoalIr.Scope.SOrg");
    return s.toString();
  }
}
