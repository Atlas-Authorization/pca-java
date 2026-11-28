// Class Sel_SelEffect
// Dafny class Sel_SelEffect compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Sel_SelEffect extends Sel {
  public dafny.DafnySequence<? extends dafny.CodePoint> _cls;
  public Sel_SelEffect (dafny.DafnySequence<? extends dafny.CodePoint> cls) {
    super();
    this._cls = cls;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Sel_SelEffect o = (Sel_SelEffect)other;
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
    s.append("GoalIr.Sel.SelEffect");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._cls));
    s.append(")");
    return s.toString();
  }
}
