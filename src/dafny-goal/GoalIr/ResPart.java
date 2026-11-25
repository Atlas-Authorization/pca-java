// Class ResPart
// Dafny class ResPart compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class ResPart {
  public ResPart() {
  }
  private static final dafny.TypeDescriptor<ResPart> _TYPE = dafny.TypeDescriptor.<ResPart>referenceWithInitializer(ResPart.class, () -> ResPart.Default());
  public static dafny.TypeDescriptor<ResPart> _typeDescriptor() {
    return (dafny.TypeDescriptor<ResPart>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final ResPart theDefault = ResPart.create_PartExact(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
  public static ResPart Default() {
    return theDefault;
  }
  public static ResPart create_PartExact(dafny.DafnySequence<? extends dafny.CodePoint> id) {
    return new ResPart_PartExact(id);
  }
  public static ResPart create_PartOneOf(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> ids) {
    return new ResPart_PartOneOf(ids);
  }
  public static ResPart create_PartRelated(dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor) {
    return new ResPart_PartRelated(rel, anchor);
  }
  public boolean is_PartExact() { return this instanceof ResPart_PartExact; }
  public boolean is_PartOneOf() { return this instanceof ResPart_PartOneOf; }
  public boolean is_PartRelated() { return this instanceof ResPart_PartRelated; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_id() {
    ResPart d = this;
    return ((ResPart_PartExact)d)._id;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_ids() {
    ResPart d = this;
    return ((ResPart_PartOneOf)d)._ids;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_rel() {
    ResPart d = this;
    return ((ResPart_PartRelated)d)._rel;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_anchor() {
    ResPart d = this;
    return ((ResPart_PartRelated)d)._anchor;
  }
}
