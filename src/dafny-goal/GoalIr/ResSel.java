// Class ResSel
// Dafny class ResSel compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class ResSel {
  public ResSel() {
  }
  private static final dafny.TypeDescriptor<ResSel> _TYPE = dafny.TypeDescriptor.<ResSel>referenceWithInitializer(ResSel.class, () -> ResSel.Default());
  public static dafny.TypeDescriptor<ResSel> _typeDescriptor() {
    return (dafny.TypeDescriptor<ResSel>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final ResSel theDefault = ResSel.create_Exact(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
  public static ResSel Default() {
    return theDefault;
  }
  public static ResSel create_Exact(dafny.DafnySequence<? extends dafny.CodePoint> id) {
    return new ResSel_Exact(id);
  }
  public static ResSel create_OneOf(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> ids) {
    return new ResSel_OneOf(ids);
  }
  public static ResSel create_Related(dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor) {
    return new ResSel_Related(rel, anchor);
  }
  public static ResSel create_AnyRes(dafny.DafnySequence<? extends dafny.CodePoint> reason) {
    return new ResSel_AnyRes(reason);
  }
  public static ResSel create_AllOf(dafny.DafnySequence<? extends ResPart> parts) {
    return new ResSel_AllOf(parts);
  }
  public boolean is_Exact() { return this instanceof ResSel_Exact; }
  public boolean is_OneOf() { return this instanceof ResSel_OneOf; }
  public boolean is_Related() { return this instanceof ResSel_Related; }
  public boolean is_AnyRes() { return this instanceof ResSel_AnyRes; }
  public boolean is_AllOf() { return this instanceof ResSel_AllOf; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_id() {
    ResSel d = this;
    return ((ResSel_Exact)d)._id;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_ids() {
    ResSel d = this;
    return ((ResSel_OneOf)d)._ids;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_rel() {
    ResSel d = this;
    return ((ResSel_Related)d)._rel;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_anchor() {
    ResSel d = this;
    return ((ResSel_Related)d)._anchor;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_reason() {
    ResSel d = this;
    return ((ResSel_AnyRes)d)._reason;
  }
  public dafny.DafnySequence<? extends ResPart> dtor_parts() {
    ResSel d = this;
    return ((ResSel_AllOf)d)._parts;
  }
}
