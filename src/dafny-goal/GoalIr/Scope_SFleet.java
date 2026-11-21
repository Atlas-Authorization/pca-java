// Class Scope_SFleet
// Dafny class Scope_SFleet compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Scope_SFleet extends Scope {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _agents;
  public Scope_SFleet (dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> agents) {
    super();
    this._agents = agents;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Scope_SFleet o = (Scope_SFleet)other;
    return true && java.util.Objects.equals(this._agents, o._agents);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._agents);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Scope.SFleet");
    s.append("(");
    s.append(dafny.Helpers.toString(this._agents));
    s.append(")");
    return s.toString();
  }
}
