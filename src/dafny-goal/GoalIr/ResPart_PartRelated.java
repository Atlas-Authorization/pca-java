// Class ResPart_PartRelated
// Dafny class ResPart_PartRelated compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResPart_PartRelated extends ResPart {
  public dafny.DafnySequence<? extends dafny.CodePoint> _rel;
  public dafny.DafnySequence<? extends dafny.CodePoint> _anchor;
  public ResPart_PartRelated (dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor) {
    super();
    this._rel = rel;
    this._anchor = anchor;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResPart_PartRelated o = (ResPart_PartRelated)other;
    return true && java.util.Objects.equals(this._rel, o._rel) && java.util.Objects.equals(this._anchor, o._anchor);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._rel);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._anchor);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ResPart.PartRelated");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._rel));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._anchor));
    s.append(")");
    return s.toString();
  }
}
