// Class Unit_UMoney
// Dafny class Unit_UMoney compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Unit_UMoney extends Unit {
  public dafny.DafnySequence<? extends dafny.CodePoint> _ccy;
  public Unit_UMoney (dafny.DafnySequence<? extends dafny.CodePoint> ccy) {
    super();
    this._ccy = ccy;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Unit_UMoney o = (Unit_UMoney)other;
    return true && java.util.Objects.equals(this._ccy, o._ccy);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ccy);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Unit.UMoney");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._ccy));
    s.append(")");
    return s.toString();
  }
}
