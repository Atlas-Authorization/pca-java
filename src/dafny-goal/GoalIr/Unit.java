// Class Unit
// Dafny class Unit compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class Unit {
  public Unit() {
  }
  private static final dafny.TypeDescriptor<Unit> _TYPE = dafny.TypeDescriptor.<Unit>referenceWithInitializer(Unit.class, () -> Unit.Default());
  public static dafny.TypeDescriptor<Unit> _typeDescriptor() {
    return (dafny.TypeDescriptor<Unit>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Unit theDefault = Unit.create_UMoney(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
  public static Unit Default() {
    return theDefault;
  }
  public static Unit create_UMoney(dafny.DafnySequence<? extends dafny.CodePoint> ccy) {
    return new Unit_UMoney(ccy);
  }
  public static Unit create_UCount() {
    return new Unit_UCount();
  }
  public static Unit create_UDuration() {
    return new Unit_UDuration();
  }
  public static Unit create_UInstant() {
    return new Unit_UInstant();
  }
  public static Unit create_UBytes() {
    return new Unit_UBytes();
  }
  public static Unit create_URatio() {
    return new Unit_URatio();
  }
  public boolean is_UMoney() { return this instanceof Unit_UMoney; }
  public boolean is_UCount() { return this instanceof Unit_UCount; }
  public boolean is_UDuration() { return this instanceof Unit_UDuration; }
  public boolean is_UInstant() { return this instanceof Unit_UInstant; }
  public boolean is_UBytes() { return this instanceof Unit_UBytes; }
  public boolean is_URatio() { return this instanceof Unit_URatio; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_ccy() {
    Unit d = this;
    return ((Unit_UMoney)d)._ccy;
  }
}
