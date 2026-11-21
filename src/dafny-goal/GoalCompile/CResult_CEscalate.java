// Class CResult_CEscalate
// Dafny class CResult_CEscalate compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class CResult_CEscalate extends CResult {
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _reasons;
  public CResult_CEscalate (dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> reasons) {
    super();
    this._reasons = reasons;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    CResult_CEscalate o = (CResult_CEscalate)other;
    return true && java.util.Objects.equals(this._reasons, o._reasons);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._reasons);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalCompile.CResult.CEscalate");
    s.append("(");
    s.append(dafny.Helpers.toString(this._reasons));
    s.append(")");
    return s.toString();
  }
}
