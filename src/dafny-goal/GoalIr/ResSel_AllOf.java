// Class ResSel_AllOf
// Dafny class ResSel_AllOf compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResSel_AllOf extends ResSel {
  public dafny.DafnySequence<? extends ResPart> _parts;
  public ResSel_AllOf (dafny.DafnySequence<? extends ResPart> parts) {
    super();
    this._parts = parts;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResSel_AllOf o = (ResSel_AllOf)other;
    return true && java.util.Objects.equals(this._parts, o._parts);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 4;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._parts);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ResSel.AllOf");
    s.append("(");
    s.append(dafny.Helpers.toString(this._parts));
    s.append(")");
    return s.toString();
  }
}
