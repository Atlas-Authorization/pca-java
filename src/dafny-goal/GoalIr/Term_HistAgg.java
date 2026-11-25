// Class Term_HistAgg
// Dafny class Term_HistAgg compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Term_HistAgg extends Term {
  public dafny.DafnySequence<? extends dafny.CodePoint> _bid;
  public Unit _u;
  public Term_HistAgg (dafny.DafnySequence<? extends dafny.CodePoint> bid, Unit u) {
    super();
    this._bid = bid;
    this._u = u;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Term_HistAgg o = (Term_HistAgg)other;
    return true && java.util.Objects.equals(this._bid, o._bid) && java.util.Objects.equals(this._u, o._u);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._bid);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._u);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Term.HistAgg");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._bid));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._u));
    s.append(")");
    return s.toString();
  }
}
