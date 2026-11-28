// Class Window_WLifetime
// Dafny class Window_WLifetime compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Window_WLifetime extends Window {
  public Window_WLifetime () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Window_WLifetime o = (Window_WLifetime)other;
    return true;
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 3;
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Window.WLifetime");
    return s.toString();
  }
}
