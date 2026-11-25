// Class Ty_TyS
// Dafny class Ty_TyS compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Ty_TyS extends Ty {
  public Ty_TyS () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Ty_TyS o = (Ty_TyS)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Ty.TyS");
    return s.toString();
  }
}
