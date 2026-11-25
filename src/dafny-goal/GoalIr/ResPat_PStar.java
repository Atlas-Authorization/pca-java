// Class ResPat_PStar
// Dafny class ResPat_PStar compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ResPat_PStar extends ResPat {
  public ResPat_PStar () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ResPat_PStar o = (ResPat_PStar)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ResPat.PStar");
    return s.toString();
  }
}
