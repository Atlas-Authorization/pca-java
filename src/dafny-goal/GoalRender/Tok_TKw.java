// Class Tok_TKw
// Dafny class Tok_TKw compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public class Tok_TKw extends Tok {
  public java.math.BigInteger _k;
  public Tok_TKw (java.math.BigInteger k) {
    super();
    this._k = k;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Tok_TKw o = (Tok_TKw)other;
    return true && java.util.Objects.equals(this._k, o._k);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._k);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalRender.Tok.TKw");
    s.append("(");
    s.append(dafny.Helpers.toString(this._k));
    s.append(")");
    return s.toString();
  }
}
