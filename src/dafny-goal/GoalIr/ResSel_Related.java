// Class ResSel_Related
// Dafny class ResSel_Related compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResSel_Related extends ResSel {
  public dafny.DafnySequence<? extends dafny.CodePoint> _rel;
  public dafny.DafnySequence<? extends dafny.CodePoint> _anchor;
  public ResSel_Related (dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor) {
    super();
    this._rel = rel;
    this._anchor = anchor;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResSel_Related o = (ResSel_Related)other;
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
    s.append("GoalIr.ResSel.Related");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._rel));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._anchor));
    s.append(")");
    return s.toString();
  }
}
