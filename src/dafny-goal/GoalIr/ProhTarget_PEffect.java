// Class ProhTarget_PEffect
// Dafny class ProhTarget_PEffect compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ProhTarget_PEffect extends ProhTarget {
  public dafny.DafnySequence<? extends dafny.CodePoint> _cls;
  public ProhTarget_PEffect (dafny.DafnySequence<? extends dafny.CodePoint> cls) {
    super();
    this._cls = cls;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ProhTarget_PEffect o = (ProhTarget_PEffect)other;
    return true && java.util.Objects.equals(this._cls, o._cls);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._cls);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ProhTarget.PEffect");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._cls));
    s.append(")");
    return s.toString();
  }
}
