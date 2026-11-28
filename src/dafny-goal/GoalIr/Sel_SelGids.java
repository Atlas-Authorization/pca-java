// Class Sel_SelGids
// Dafny class Sel_SelGids compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Sel_SelGids extends Sel {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _gids;
  public Sel_SelGids (dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> gids) {
    super();
    this._gids = gids;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Sel_SelGids o = (Sel_SelGids)other;
    return true && java.util.Objects.equals(this._gids, o._gids);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._gids);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Sel.SelGids");
    s.append("(");
    s.append(dafny.Helpers.toString(this._gids));
    s.append(")");
    return s.toString();
  }
}
