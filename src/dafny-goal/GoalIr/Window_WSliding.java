// Class Window_WSliding
// Dafny class Window_WSliding compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Window_WSliding extends Window {
  public java.math.BigInteger _ms;
  public Window_WSliding (java.math.BigInteger ms) {
    super();
    this._ms = ms;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Window_WSliding o = (Window_WSliding)other;
    return true && java.util.Objects.equals(this._ms, o._ms);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 1;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ms);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Window.WSliding");
    s.append("(");
    s.append(dafny.Helpers.toString(this._ms));
    s.append(")");
    return s.toString();
  }
}
