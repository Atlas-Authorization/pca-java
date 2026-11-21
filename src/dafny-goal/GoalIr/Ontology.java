// Class Ontology
// Dafny class Ontology compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class Ontology {
  public dafny.DafnySequence<? extends VerbDecl> _verbs;
  public dafny.DafnySequence<? extends RelDecl> _rels;
  public Ontology (dafny.DafnySequence<? extends VerbDecl> verbs, dafny.DafnySequence<? extends RelDecl> rels) {
    this._verbs = verbs;
    this._rels = rels;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other == null) return false;
    if (getClass() != other.getClass()) return false;
    Ontology o = (Ontology)other;
    return true && java.util.Objects.equals(this._verbs, o._verbs) && java.util.Objects.equals(this._rels, o._rels);
  }
  @Override
  public int hashCode() {
    long hash = 5381;
    hash = ((hash << 5) + hash) + 0;
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._verbs);
    hash = ((hash << 5) + hash) + java.util.Objects.hashCode(this._rels);
    return (int)hash;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("GoalIr.Ontology.Ontology");
    s.append("(");
    s.append(dafny.Helpers.toString(this._verbs));
    s.append(", ");
    s.append(dafny.Helpers.toString(this._rels));
    s.append(")");
    return s.toString();
  }
  private static final dafny.TypeDescriptor<Ontology> _TYPE = dafny.TypeDescriptor.<Ontology>referenceWithInitializer(Ontology.class, () -> Ontology.Default());
  public static dafny.TypeDescriptor<Ontology> _typeDescriptor() {
    return (dafny.TypeDescriptor<Ontology>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final Ontology theDefault = Ontology.create(dafny.DafnySequence.<VerbDecl> empty(VerbDecl._typeDescriptor()), dafny.DafnySequence.<RelDecl> empty(RelDecl._typeDescriptor()));
  public static Ontology Default() {
    return theDefault;
  }
  public static Ontology create(dafny.DafnySequence<? extends VerbDecl> verbs, dafny.DafnySequence<? extends RelDecl> rels) {
    return new Ontology(verbs, rels);
  }
  public static Ontology create_Ontology(dafny.DafnySequence<? extends VerbDecl> verbs, dafny.DafnySequence<? extends RelDecl> rels) {
    return create(verbs, rels);
  }
  public boolean is_Ontology() { return true; }
  public dafny.DafnySequence<? extends VerbDecl> dtor_verbs() {
    return this._verbs;
  }
  public dafny.DafnySequence<? extends RelDecl> dtor_rels() {
    return this._rels;
  }
}
