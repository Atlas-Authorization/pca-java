// Class V_VSet
// Dafny class V_VSet compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class V_VSet extends V {
  public dafny.DafnySequence<? extends Atom> _items;
  public V_VSet (dafny.DafnySequence<? extends Atom> items) {
    super();
    this._items = items;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    V_VSet o = (V_VSet)other;
    return true && java.util.Objects.equals(this._items, o._items);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 2;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._items);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.V.VSet");
    s.append("(");
    s.append(dafny.Helpers.toString(this._items));
    s.append(")");
    return s.toString();
  }
}
