// Class Window_WTask
// Dafny class Window_WTask compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Window_WTask extends Window {
  public Window_WTask () {
    super();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Window_WTask o = (Window_WTask)other;
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
    s.append("GoalIr.Window.WTask");
    return s.toString();
  }
}
