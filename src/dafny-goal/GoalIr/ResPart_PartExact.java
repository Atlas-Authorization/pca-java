// Class ResPart_PartExact
// Dafny class ResPart_PartExact compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResPart_PartExact extends ResPart {
  public dafny.DafnySequence<? extends dafny.CodePoint> _id;
  public ResPart_PartExact (dafny.DafnySequence<? extends dafny.CodePoint> id) {
    super();
    this._id = id;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResPart_PartExact o = (ResPart_PartExact)other;
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
    s.append("GoalIr.ResPart.PartExact");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._id));
    s.append(")");
    return s.toString();
  }
}
