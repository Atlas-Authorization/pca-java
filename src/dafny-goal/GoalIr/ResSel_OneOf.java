// Class ResSel_OneOf
// Dafny class ResSel_OneOf compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResSel_OneOf extends ResSel {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _ids;
  public ResSel_OneOf (dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> ids) {
    super();
    this._ids = ids;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResSel_OneOf o = (ResSel_OneOf)other;
    return true && java.util.Objects.equals(this._ids, o._ids);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ids);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ResSel.OneOf");
    s.append("(");
    s.append(dafny.Helpers.toString(this._ids));
    s.append(")");
    return s.toString();
  }
}
