// Class Tok_TS
// Dafny class Tok_TS compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public class Tok_TS extends Tok {
  public dafny.DafnySequence<? extends dafny.CodePoint> _s;
  public Tok_TS (dafny.DafnySequence<? extends dafny.CodePoint> s) {
    super();
    this._s = s;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Tok_TS o = (Tok_TS)other;
    return true && java.util.Objects.equals(this._s, o._s);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._s);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder ss = new StringBuilder();
    ss.append("GoalRender.Tok.TS");
    ss.append("(");
    ss.append(dafny.Helpers.ToStringLiteral(this._s));
    ss.append(")");
    return ss.toString();
  }
}
