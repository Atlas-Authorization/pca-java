// Class Window_WPeriod
// Dafny class Window_WPeriod compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Window_WPeriod extends Window {
  public java.math.BigInteger _ms;
  public java.math.BigInteger _t0;
  public Window_WPeriod (java.math.BigInteger ms, java.math.BigInteger t0) {
    super();
    this._ms = ms;
    this._t0 = t0;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Window_WPeriod o = (Window_WPeriod)other;
    return true && java.util.Objects.equals(this._ms, o._ms) && java.util.Objects.equals(this._t0, o._t0);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ms);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._t0);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Window.WPeriod");
    s.append("(");
    s.append(dafny.Helpers.toString(this._ms));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._t0));
    s.append(")");
    return s.toString();
  }
}
