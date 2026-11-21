// Class V_VS
// Dafny class V_VS compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class V_VS extends V {
  public dafny.DafnySequence<? extends dafny.CodePoint> _s;
  public V_VS (dafny.DafnySequence<? extends dafny.CodePoint> s) {
    super();
    this._s = s;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    V_VS o = (V_VS)other;
    return true && java.util.Objects.equals(this._s, o._s);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._s);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder ss = new StringBuilder();
    ss.append("GoalIr.V.VS");
    ss.append("(");
    ss.append(dafny.Helpers.ToStringLiteral(this._s));
    ss.append(")");
    return ss.toString();
  }
}
