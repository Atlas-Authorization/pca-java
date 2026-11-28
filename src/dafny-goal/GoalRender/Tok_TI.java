// Class Tok_TI
// Dafny class Tok_TI compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public class Tok_TI extends Tok {
  public java.math.BigInteger _i;
  public Tok_TI (java.math.BigInteger i) {
    super();
    this._i = i;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Tok_TI o = (Tok_TI)other;
    return true && java.util.Objects.equals(this._i, o._i);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._i);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalRender.Tok.TI");
    s.append("(");
    s.append(dafny.Helpers.toString(this._i));
    s.append(")");
    return s.toString();
  }
}
