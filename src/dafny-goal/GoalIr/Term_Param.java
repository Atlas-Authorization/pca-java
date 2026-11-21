// Class Term_Param
// Dafny class Term_Param compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Term_Param extends Term {
  public dafny.DafnySequence<? extends dafny.CodePoint> _path;
  public Ty _ty;
  public Term_Param (dafny.DafnySequence<? extends dafny.CodePoint> path, Ty ty) {
    super();
    this._path = path;
    this._ty = ty;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Term_Param o = (Term_Param)other;
    return true && java.util.Objects.equals(this._path, o._path) && java.util.Objects.equals(this._ty, o._ty);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._path);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._ty);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Term.Param");
    s.append("(");
    s.append(dafny.Helpers.ToStringLiteral(this._path));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._ty));
    s.append(")");
    return s.toString();
  }
}
