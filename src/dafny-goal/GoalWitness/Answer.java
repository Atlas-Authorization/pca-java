// Class Answer
// Dafny class Answer compiled into Java
package GoalWitness;

@SuppressWarnings({"unchecked", "deprecation"})
public class Answer {
  public boolean _sigOk;
  public dafny.DafnySequence<? extends dafny.CodePoint> _policyDigest;
  public dafny.DafnySequence<? extends dafny.CodePoint> _actionDigest;
  public dafny.DafnySequence<? extends dafny.CodePoint> _histHead;
  public Answer (boolean sigOk, dafny.DafnySequence<? extends dafny.CodePoint> policyDigest, dafny.DafnySequence<? extends dafny.CodePoint> actionDigest, dafny.DafnySequence<? extends dafny.CodePoint> histHead) {
    this._sigOk = sigOk;
    this._policyDigest = policyDigest;
    this._actionDigest = actionDigest;
    this._histHead = histHead;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Answer o = (Answer)other;
    return true && this._sigOk == o._sigOk && java.util.Objects.equals(this._policyDigest, o._policyDigest) && java.util.Objects.equals(this._actionDigest, o._actionDigest) && java.util.Objects.equals(this._histHead, o._histHead);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + Boolean.hashCode(this._sigOk);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._policyDigest);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._actionDigest);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._histHead);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalWitness.Answer.Answer");
    s.append("(");
    s.append(this._sigOk);
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._policyDigest));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._actionDigest));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._histHead));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Answer> _TYPE = dafny.TypeDescriptor.<Answer>referenceWithInitializer(Answer.class, () -> Answer.Default());
  public static dafny.TypeDescriptor<Answer> _typeDescriptor() {
    return (dafny.TypeDescriptor<Answer>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Answer theDefault = Answer.create(false, dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR));
  public static Answer Default() {
    return theDefault;
  }
  public static Answer create(boolean sigOk, dafny.DafnySequence<? extends dafny.CodePoint> policyDigest, dafny.DafnySequence<? extends dafny.CodePoint> actionDigest, dafny.DafnySequence<? extends dafny.CodePoint> histHead) {
    return new Answer(sigOk, policyDigest, actionDigest, histHead);
  }
  public static Answer create_Answer(boolean sigOk, dafny.DafnySequence<? extends dafny.CodePoint> policyDigest, dafny.DafnySequence<? extends dafny.CodePoint> actionDigest, dafny.DafnySequence<? extends dafny.CodePoint> histHead) {
    return create(sigOk, policyDigest, actionDigest, histHead);
  }
  public boolean is_Answer() { return true; }
  public boolean dtor_sigOk() {
    return this._sigOk;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_policyDigest() {
    return this._policyDigest;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_actionDigest() {
    return this._actionDigest;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_histHead() {
    return this._histHead;
  }
}
