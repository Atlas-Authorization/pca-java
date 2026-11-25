// Class ProhTarget_PVerb
// Dafny class ProhTarget_PVerb compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class ProhTarget_PVerb extends ProhTarget {
  public dafny.DafnySequence<? extends dafny.CodePoint> _verb;
  public ProhTarget_PVerb (dafny.DafnySequence<? extends dafny.CodePoint> verb) {
    super();
    this._verb = verb;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    ProhTarget_PVerb o = (ProhTarget_PVerb)other;
    return true && java.util.Objects.equals(this._verb, o._verb);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verb);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.ProhTarget.PVerb");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._verb));
    s.append(")");
    return s.toString();
  }
}
