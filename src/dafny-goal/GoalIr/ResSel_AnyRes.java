// Class ResSel_AnyRes
// Dafny class ResSel_AnyRes compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResSel_AnyRes extends ResSel {
  public dafny.DafnySequence<? extends dafny.CodePoint> _reason;
  public ResSel_AnyRes (dafny.DafnySequence<? extends dafny.CodePoint> reason) {
    super();
    this._reason = reason;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResSel_AnyRes o = (ResSel_AnyRes)other;
    return true && java.util.Objects.equals(this._reason, o._reason);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._reason);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ResSel.AnyRes");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._reason));
    s.append(")");
    return s.toString();
  }
}
