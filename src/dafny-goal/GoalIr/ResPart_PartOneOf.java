// Class ResPart_PartOneOf
// Dafny class ResPart_PartOneOf compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResPart_PartOneOf extends ResPart {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _ids;
  public ResPart_PartOneOf (dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> ids) {
    super();
    this._ids = ids;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResPart_PartOneOf o = (ResPart_PartOneOf)other;
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
    s.append("GoalIr.ResPart.PartOneOf");
    s.append("(");
    s.append(dafny.Helpers.toString(this._ids));
    s.append(")");
    return s.toString();
  }
}
