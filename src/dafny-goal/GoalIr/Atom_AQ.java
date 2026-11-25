// Class Atom_AQ
// Dafny class Atom_AQ compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Atom_AQ extends Atom {
  public Q _q;
  public Atom_AQ (Q q) {
    super();
    this._q = q;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Atom_AQ o = (Atom_AQ)other;
    return true && java.util.Objects.equals(this._q, o._q);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._q);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Atom.AQ");
    s.append("(");
    s.append(dafny.Helpers.toString(this._q));
    s.append(")");
    return s.toString();
  }
}
