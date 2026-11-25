// Class Hist
// Dafny class Hist compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Hist {
  public dafny.DafnySequence<? extends Adm> _adms;
  public java.math.BigInteger _last;
  public dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends Q> _aggs;
  public Hist (dafny.DafnySequence<? extends Adm> adms, java.math.BigInteger last, dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends Q> aggs) {
    this._adms = adms;
    this._last = last;
    this._aggs = aggs;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Hist o = (Hist)other;
    return true && java.util.Objects.equals(this._adms, o._adms) && java.util.Objects.equals(this._last, o._last) && java.util.Objects.equals(this._aggs, o._aggs);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._adms);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._last);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._aggs);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Hist.Hist");
    s.append("(");
    s.append(dafny.Helpers.toString(this._adms));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._last));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._aggs));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Hist> _TYPE = dafny.TypeDescriptor.<Hist>referenceWithInitializer(Hist.class, () -> Hist.Default());
  public static dafny.TypeDescriptor<Hist> _typeDescriptor() {
    return (dafny.TypeDescriptor<Hist>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Hist theDefault = Hist.create(dafny.DafnySequence.<Adm> empty(Adm._typeDescriptor()), java.math.BigInteger.ZERO, dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>,Q> empty());
  public static Hist Default() {
    return theDefault;
  }
  public static Hist create(dafny.DafnySequence<? extends Adm> adms, java.math.BigInteger last, dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends Q> aggs) {
    return new Hist(adms, last, aggs);
  }
  public static Hist create_Hist(dafny.DafnySequence<? extends Adm> adms, java.math.BigInteger last, dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends Q> aggs) {
    return create(adms, last, aggs);
  }
  public boolean is_Hist() { return true; }
  public dafny.DafnySequence<? extends Adm> dtor_adms() {
    return this._adms;
  }
  public java.math.BigInteger dtor_last() {
    return this._last;
  }
  public dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends Q> dtor_aggs() {
    return this._aggs;
  }
}
