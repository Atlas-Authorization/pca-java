// Class ProhTarget
// Dafny class ProhTarget compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class ProhTarget {
  public ProhTarget() {
  }
  private static final dafny.TypeDescriptor<ProhTarget> _TYPE = dafny.TypeDescriptor.<ProhTarget>referenceWithInitializer(ProhTarget.class, () -> ProhTarget.Default());
  public static dafny.TypeDescriptor<ProhTarget> _typeDescriptor() {
    return (dafny.TypeDescriptor<ProhTarget>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final ProhTarget theDefault = ProhTarget.create_PVerb(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
  public static ProhTarget Default() {
    return theDefault;
  }
  public static ProhTarget create_PVerb(dafny.DafnySequence<? extends dafny.CodePoint> verb) {
    return new ProhTarget_PVerb(verb);
  }
  public static ProhTarget create_PEffect(dafny.DafnySequence<? extends dafny.CodePoint> cls) {
    return new ProhTarget_PEffect(cls);
  }
  public boolean is_PVerb() { return this instanceof ProhTarget_PVerb; }
  public boolean is_PEffect() { return this instanceof ProhTarget_PEffect; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    ProhTarget d = this;
    return ((ProhTarget_PVerb)d)._verb;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_cls() {
    ProhTarget d = this;
    return ((ProhTarget_PEffect)d)._cls;
  }
}
