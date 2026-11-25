// Class CResult_Compiled
// Dafny class CResult_Compiled compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class CResult_Compiled extends CResult {
  public Pol _p;
  public CResult_Compiled (Pol p) {
    super();
    this._p = p;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    CResult_Compiled o = (CResult_Compiled)other;
    return true && java.util.Objects.equals(this._p, o._p);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._p);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalCompile.CResult.Compiled");
    s.append("(");
    s.append(dafny.Helpers.toString(this._p));
    s.append(")");
    return s.toString();
  }
}
