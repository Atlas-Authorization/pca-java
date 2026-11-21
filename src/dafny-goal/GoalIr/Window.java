// Class Window
// Dafny class Window compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Window {
  public Window() {
  }
  private static final dafny.TypeDescriptor<Window> _TYPE = dafny.TypeDescriptor.<Window>referenceWithInitializer(Window.class, () -> Window.Default());
  public static dafny.TypeDescriptor<Window> _typeDescriptor() {
    return (dafny.TypeDescriptor<Window>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Window theDefault = Window.create_WTask();
  public static Window Default() {
    return theDefault;
  }
  public static Window create_WTask() {
    return new Window_WTask();
  }
  public static Window create_WSliding(java.math.BigInteger ms) {
    return new Window_WSliding(ms);
  }
  public static Window create_WPeriod(java.math.BigInteger ms, java.math.BigInteger t0) {
    return new Window_WPeriod(ms, t0);
  }
  public static Window create_WLifetime() {
    return new Window_WLifetime();
  }
  public boolean is_WTask() { return this instanceof Window_WTask; }
  public boolean is_WSliding() { return this instanceof Window_WSliding; }
  public boolean is_WPeriod() { return this instanceof Window_WPeriod; }
  public boolean is_WLifetime() { return this instanceof Window_WLifetime; }
  public java.math.BigInteger dtor_ms() {
    Window d = this;
    if (d instanceof Window_WSliding) { return ((Window_WSliding)d)._ms; }
    return ((Window_WPeriod)d)._ms;
  }
  public java.math.BigInteger dtor_t0() {
    Window d = this;
    return ((Window_WPeriod)d)._t0;
  }
}
