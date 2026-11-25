// Class Act
// Dafny class Act compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Act {
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public dafny.DafnySequence<? extends dafny.CodePoint> _res;
  public dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends V> _params;
  public java.math.BigInteger _t;
  public dafny.DafnySequence<? extends dafny.CodePoint> _sess;
  public dafny.DafnySequence<? extends dafny.CodePoint> _prin;
  public dafny.DafnySequence<? extends dafny.CodePoint> _org;
  public dafny.DafnySequence<? extends dafny.CodePoint> _agent;
  public java.math.BigInteger _depth;
  public Act (dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> res, dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends V> params, java.math.BigInteger t, dafny.DafnySequence<? extends dafny.CodePoint> sess, dafny.DafnySequence<? extends dafny.CodePoint> prin, dafny.DafnySequence<? extends dafny.CodePoint> org, dafny.DafnySequence<? extends dafny.CodePoint> agent, java.math.BigInteger depth) {
    this._verb = verb;
    this._res = res;
    this._params = params;
    this._t = t;
    this._sess = sess;
    this._prin = prin;
    this._org = org;
    this._agent = agent;
    this._depth = depth;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Act o = (Act)other;
    return true && java.util.Objects.equals(this._verb, o._verb) && java.util.Objects.equals(this._res, o._res) && java.util.Objects.equals(this._params, o._params) && java.util.Objects.equals(this._t, o._t) && java.util.Objects.equals(this._sess, o._sess) && java.util.Objects.equals(this._prin, o._prin) && java.util.Objects.equals(this._org, o._org) && java.util.Objects.equals(this._agent, o._agent) && java.util.Objects.equals(this._depth, o._depth);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verb);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._res);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._params);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._t);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._sess);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._prin);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._org);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._agent);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._depth);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Act.Act");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._verb));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._res));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._params));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._t));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._sess));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._prin));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._org));
    s.append(", ");
    s.append(dafny.Helpers.ToStringLiteral(this._agent));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._depth));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Act> _TYPE = dafny.TypeDescriptor.<Act>referenceWithInitializer(Act.class, () -> Act.Default());
  public static dafny.TypeDescriptor<Act> _typeDescriptor() {
    return (dafny.TypeDescriptor<Act>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Act theDefault = Act.create(dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>,V> empty(), java.math.BigInteger.ZERO, dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.<dafny.CodePoint> empty(dafny.TypeDescriptor.UNICODE_CHAR), java.math.BigInteger.ZERO);
  public static Act Default() {
    return theDefault;
  }
  public static Act create(dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> res, dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends V> params, java.math.BigInteger t, dafny.DafnySequence<? extends dafny.CodePoint> sess, dafny.DafnySequence<? extends dafny.CodePoint> prin, dafny.DafnySequence<? extends dafny.CodePoint> org, dafny.DafnySequence<? extends dafny.CodePoint> agent, java.math.BigInteger depth) {
    return new Act(verb, res, params, t, sess, prin, org, agent, depth);
  }
  public static Act create_Act(dafny.DafnySequence<? extends dafny.CodePoint> verb, dafny.DafnySequence<? extends dafny.CodePoint> res, dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends V> params, java.math.BigInteger t, dafny.DafnySequence<? extends dafny.CodePoint> sess, dafny.DafnySequence<? extends dafny.CodePoint> prin, dafny.DafnySequence<? extends dafny.CodePoint> org, dafny.DafnySequence<? extends dafny.CodePoint> agent, java.math.BigInteger depth) {
    return create(verb, res, params, t, sess, prin, org, agent, depth);
  }
  public boolean is_Act() { return true; }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_verb() {
    return this._verb;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_res() {
    return this._res;
  }
  public dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends V> dtor_params() {
    return this._params;
  }
  public java.math.BigInteger dtor_t() {
    return this._t;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_sess() {
    return this._sess;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_prin() {
    return this._prin;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_org() {
    return this._org;
  }
  public dafny.DafnySequence<? extends dafny.CodePoint> dtor_agent() {
    return this._agent;
  }
  public java.math.BigInteger dtor_depth() {
    return this._depth;
  }
}
