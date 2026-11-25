// Class Goal
// Dafny class Goal compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Goal {
  public java.math.BigInteger _v;
  public dafny.DafnySequence<? extends dafny.CodePoint> _principal;
  public dafny.DafnySequence<? extends dafny.CodePoint> _ontDigest;
  public dafny.DafnySequence<? extends dafny.CodePoint> _nlDigest;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _sources;
  public dafny.DafnySequence<? extends Grant> _grants;
  public dafny.DafnySequence<? extends Prohibit> _prohibits;
  public dafny.DafnySequence<? extends Bound> _bounds;
  public Validity _validity;
  public Delegation _deleg;
  public dafny.DafnySequence<? extends Cond> _escalateOn;
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _wildcardAck;
  public dafny.DafnySequence<? extends Hole> _holes;
  public Goal (java.math.BigInteger v, dafny.DafnySequence<? extends dafny.CodePoint> principal, dafny.DafnySequence<? extends dafny.CodePoint> ontDigest, dafny.DafnySequence<? extends dafny.CodePoint> nlDigest, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> sources, dafny.DafnySequence<? extends Grant> grants, dafny.DafnySequence<? extends Prohibit> prohibits, dafny.DafnySequence<? extends Bound> bounds, Validity validity, Delegation deleg, dafny.DafnySequence<? extends Cond> escalateOn, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> wildcardAck, dafny.DafnySequence<? extends Hole> holes) {
    this._v = v;
    this._principal = principal;
    this._ontDigest = ontDigest;
    this._nlDigest = nlDigest;
    this._sources = sources;
    this._grants = grants;
    this._prohibits = prohibits;
    this._bounds = bounds;
    this._validity = validity;
    this._deleg = deleg;
    this._escalateOn = escalateOn;
    this._wildcardAck = wildcardAck;
    this._holes = holes;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Goal o = (Goal)other;
    return true && java.util.Objects.equals(this._v, o._v) && java.util.Objects.equals(this._principal, o._principal) && java.util.Objects.equals(this._ontDigest, o._ontDigest) && java.util.Objects.equals(this._nlDigest, o._nlDigest) && java.util.Objects.equals(this._sources, o._sources) && java.util.Objects.equals(this._grants, o._grants) && java.util.Objects.equals(this._prohibits, o._prohibits) && java.util.Objects.equals(this._bounds, o._bounds) && java.util.Objects.equals(this._validity, o._validity) && java.util.Objects.equals(this._deleg, o._deleg) && java.util.Objects.equals(this._escalateOn, o._escalateOn) && java.util.Objects.equals(this._wildcardAck, o._wildcardAck) && java.util.Objects.equals(this._holes, o._holes);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._v);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._principal);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ontDigest);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._nlDigest);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._sources);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._grants);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._prohibits);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._bounds);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._validity);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._deleg);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._escalateOn);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._wildcardAck);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._holes);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Goal.Goal");
    s.append("(");
    s.append(dafny.Helpers.toString(this._v));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._principal));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._ontDigest));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._nlDigest));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._sources));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._grants));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._prohibits));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._bounds));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._validity));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._deleg));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._escalateOn));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._wildcardAck));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._holes));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Goal> _TYPE = dafny.TypeDescriptor.<Goal>referenceWithInitializer(Goal.class, () -> Goal.Default());
  public static dafny.TypeDescriptor<Goal> _typeDescriptor() {
    return (dafny.TypeDescriptor<Goal>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Goal theDefault = Goal.create(java.math.BigInteger.ZERO, dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.DafnySequence.<Grant> empty(Grant._typeDescriptor()), dafny.DafnySequence.<Prohibit> empty(Prohibit._typeDescriptor()), dafny.DafnySequence.<Bound> empty(Bound._typeDescriptor()), Validity.Default(), Delegation.Default(), dafny.DafnySequence.<Cond> empty(Cond._typeDescriptor()), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.DafnySequence.<Hole> empty(Hole._typeDescriptor()));
  public static Goal Default() {
    return theDefault;
  }
  public static Goal create(java.math.BigInteger v, dafny.DafnySequence<? extends dafny.CodePoint> principal, dafny.DafnySequence<? extends dafny.CodePoint> ontDigest, dafny.DafnySequence<? extends dafny.CodePoint> nlDigest, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> sources, dafny.DafnySequence<? extends Grant> grants, dafny.DafnySequence<? extends Prohibit> prohibits, dafny.DafnySequence<? extends Bound> bounds, Validity validity, Delegation deleg, dafny.DafnySequence<? extends Cond> escalateOn, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> wildcardAck, dafny.DafnySequence<? extends Hole> holes) {
    return new Goal(v, principal, ontDigest, nlDigest, sources, grants, prohibits, bounds, validity, deleg, escalateOn, wildcardAck, holes);
  }
  public static Goal create_Goal(java.math.BigInteger v, dafny.DafnySequence<? extends dafny.CodePoint> principal, dafny.DafnySequence<? extends dafny.CodePoint> ontDigest, dafny.DafnySequence<? extends dafny.CodePoint> nlDigest, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> sources, dafny.DafnySequence<? extends Grant> grants, dafny.DafnySequence<? extends Prohibit> prohibits, dafny.DafnySequence<? extends Bound> bounds, Validity validity, Delegation deleg, dafny.DafnySequence<? extends Cond> escalateOn, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> wildcardAck, dafny.DafnySequence<? extends Hole> holes) {
    return create(v, principal, ontDigest, nlDigest, sources, grants, prohibits, bounds, validity, deleg, escalateOn, wildcardAck, holes);
  }
  public boolean is_Goal() { return true; }
  public java.math.BigInteger dtor_v() {
    return this._v;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_principal() {
    return this._principal;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_ontDigest() {
    return this._ontDigest;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_nlDigest() {
    return this._nlDigest;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_sources() {
    return this._sources;
  }
  public dafny.DafnySequence<? extends Grant> dtor_grants() {
    return this._grants;
  }
  public dafny.DafnySequence<? extends Prohibit> dtor_prohibits() {
    return this._prohibits;
  }
  public dafny.DafnySequence<? extends Bound> dtor_bounds() {
    return this._bounds;
  }
  public Validity dtor_validity() {
    return this._validity;
  }
  public Delegation dtor_deleg() {
    return this._deleg;
  }
  public dafny.DafnySequence<? extends Cond> dtor_escalateOn() {
    return this._escalateOn;
  }
  public dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> dtor_wildcardAck() {
    return this._wildcardAck;
  }
  public dafny.DafnySequence<? extends Hole> dtor_holes() {
    return this._holes;
  }
}
