// Class Pol
// Dafny class Pol compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class Pol {
  public dafny.DafnySequence<? extends LPred> _preds;
  public dafny.DafnySequence<? extends LProh> _prohs;
  public dafny.DafnySequence<? extends LCeil> _ceils;
  public dafny.DafnySequence<? extends NC> _escs;
  public GoalIr.Validity _validity;
  public GoalIr.Delegation _deleg;
  public Pol (dafny.DafnySequence<? extends LPred> preds, dafny.DafnySequence<? extends LProh> prohs, dafny.DafnySequence<? extends LCeil> ceils, dafny.DafnySequence<? extends NC> escs, GoalIr.Validity validity, GoalIr.Delegation deleg) {
    this._preds = preds;
    this._prohs = prohs;
    this._ceils = ceils;
    this._escs = escs;
    this._validity = validity;
    this._deleg = deleg;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Pol o = (Pol)other;
    return true && java.util.Objects.equals(this._preds, o._preds) && java.util.Objects.equals(this._prohs, o._prohs) && java.util.Objects.equals(this._ceils, o._ceils) && java.util.Objects.equals(this._escs, o._escs) && java.util.Objects.equals(this._validity, o._validity) && java.util.Objects.equals(this._deleg, o._deleg);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._preds);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._prohs);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ceils);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._escs);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._validity);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._deleg);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalCompile.Pol.Pol");
    s.append("(");
    s.append(dafny.Helpers.toString(this._preds));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._prohs));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._ceils));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._escs));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._validity));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._deleg));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Pol> _TYPE = dafny.TypeDescriptor.<Pol>referenceWithInitializer(Pol.class, () -> Pol.Default());
  public static dafny.TypeDescriptor<Pol> _typeDescriptor() {
    return (dafny.TypeDescriptor<Pol>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Pol theDefault = Pol.create(dafny.DafnySequence.<LPred> empty(LPred._typeDescriptor()), dafny.DafnySequence.<LProh> empty(LProh._typeDescriptor()), dafny.DafnySequence.<LCeil> empty(LCeil._typeDescriptor()), dafny.DafnySequence.<NC> empty(NC._typeDescriptor()), GoalIr.Validity.Default(), GoalIr.Delegation.Default());
  public static Pol Default() {
    return theDefault;
  }
  public static Pol create(dafny.DafnySequence<? extends LPred> preds, dafny.DafnySequence<? extends LProh> prohs, dafny.DafnySequence<? extends LCeil> ceils, dafny.DafnySequence<? extends NC> escs, GoalIr.Validity validity, GoalIr.Delegation deleg) {
    return new Pol(preds, prohs, ceils, escs, validity, deleg);
  }
  public static Pol create_Pol(dafny.DafnySequence<? extends LPred> preds, dafny.DafnySequence<? extends LProh> prohs, dafny.DafnySequence<? extends LCeil> ceils, dafny.DafnySequence<? extends NC> escs, GoalIr.Validity validity, GoalIr.Delegation deleg) {
    return create(preds, prohs, ceils, escs, validity, deleg);
  }
  public boolean is_Pol() { return true; }
  public dafny.DafnySequence<? extends LPred> dtor_preds() {
    return this._preds;
  }
  public dafny.DafnySequence<? extends LProh> dtor_prohs() {
    return this._prohs;
  }
  public dafny.DafnySequence<? extends LCeil> dtor_ceils() {
    return this._ceils;
  }
  public dafny.DafnySequence<? extends NC> dtor_escs() {
    return this._escs;
  }
  public GoalIr.Validity dtor_validity() {
    return this._validity;
  }
  public GoalIr.Delegation dtor_deleg() {
    return this._deleg;
  }
}
