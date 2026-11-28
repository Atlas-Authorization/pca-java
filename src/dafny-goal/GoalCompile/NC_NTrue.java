// Class NC_NTrue
// Dafny class NC_NTrue compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class NC_NTrue extends NC {
  public NC_NTrue () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    NC_NTrue o = (NC_NTrue)other;
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
    s.append("GoalCompile.NC.NTrue");
    return s.toString();
  }
}
