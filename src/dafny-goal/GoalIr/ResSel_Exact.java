// Class ResSel_Exact
// Dafny class ResSel_Exact compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResSel_Exact extends ResSel {
  public dafny.DafnySequence<? extends dafny.CodePoint> _id;
  public ResSel_Exact (dafny.DafnySequence<? extends dafny.CodePoint> id) {
    super();
    this._id = id;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResSel_Exact o = (ResSel_Exact)other;
    return true && java.util.Objects.equals(this._id, o._id);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._id);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ResSel.Exact");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._id));
    s.append(")");
    return s.toString();
  }
}
