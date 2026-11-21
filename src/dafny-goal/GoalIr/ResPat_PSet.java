// Class ResPat_PSet
// Dafny class ResPat_PSet compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResPat_PSet extends ResPat {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _ids;
  public ResPat_PSet (dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> ids) {
    super();
    this._ids = ids;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResPat_PSet o = (ResPat_PSet)other;
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
    s.append("GoalIr.ResPat.PSet");
    s.append("(");
    s.append(dafny.Helpers.toString(this._ids));
    s.append(")");
    return s.toString();
  }
}
