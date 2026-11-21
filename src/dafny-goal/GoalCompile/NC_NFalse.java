// Class NC_NFalse
// Dafny class NC_NFalse compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class NC_NFalse extends NC {
  public NC_NFalse () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    NC_NFalse o = (NC_NFalse)other;
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
    s.append("GoalCompile.NC.NFalse");
    return s.toString();
  }
}
