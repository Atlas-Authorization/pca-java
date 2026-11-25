// Class __default
// Dafny class __default compiled into Java
package GoalIr;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static java.math.BigInteger MeetD(java.math.BigInteger a, java.math.BigInteger b)
  {
    if ((a).compareTo(b) <= 0) {
      return a;
    } else {
      return b;
    }
  }
  public static java.math.BigInteger JoinD(java.math.BigInteger a, java.math.BigInteger b)
  {
    if ((a).compareTo(b) >= 0) {
      return a;
    } else {
      return b;
    }
  }
  public static java.math.BigInteger AndK(java.math.BigInteger a, java.math.BigInteger b)
  {
    if ((a).compareTo(b) <= 0) {
      return a;
    } else {
      return b;
    }
  }
  public static java.math.BigInteger OrK(java.math.BigInteger a, java.math.BigInteger b)
  {
    if ((a).compareTo(b) >= 0) {
      return a;
    } else {
      return b;
    }
  }
  public static java.math.BigInteger NotK(java.math.BigInteger a) {
    return (java.math.BigInteger.valueOf(2L)).subtract(a);
  }
  public static java.math.BigInteger B2T(boolean b) {
    if (b) {
      return __default.KT();
    } else {
      return __default.KF();
    }
  }
  public static java.math.BigInteger DecOfTri(java.math.BigInteger t) {
    return t;
  }
  public static V AtomV(Atom a) {
    Atom _source0 = a;
    if (_source0.is_AQ()) {
      Q _0___mcc_h0 = ((GoalIr.Atom_AQ)_source0)._q;
      Q _1_q = _0___mcc_h0;
      return V.create_VQ(_1_q);
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.Atom_AS)_source0)._s;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_s = _2___mcc_h1;
      return V.create_VS(_3_s);
    }
  }
  public static Option<Ty> TypeOfV(V v) {
    V _source0 = v;
    if (_source0.is_VQ()) {
      Q _0___mcc_h0 = ((GoalIr.V_VQ)_source0)._q;
      Q _1_q = _0___mcc_h0;
      return Option.<Ty>create_Some(Ty._typeDescriptor(), Ty.create_TyQ((_1_q).dtor_u()));
    } else if (_source0.is_VS()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.V_VS)_source0)._s;
      return Option.<Ty>create_Some(Ty._typeDescriptor(), Ty.create_TyS());
    } else {
      dafny.DafnySequence<? extends Atom> _3___mcc_h2 = ((GoalIr.V_VSet)_source0)._items;
      return Option.<Ty>create_None(Ty._typeDescriptor());
    }
  }
  public static boolean ResOk(ResPat p, dafny.DafnySequence<? extends dafny.CodePoint> r)
  {
    ResPat _source0 = p;
    if (_source0.is_PStar()) {
      return true;
    } else {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.ResPat_PSet)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_ids = _0___mcc_h0;
      return (_1_ids).contains(r);
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> RelMembers(dafny.DafnySequence<? extends RelDecl> rels, dafny.DafnySequence<? extends dafny.CodePoint> rel, dafny.DafnySequence<? extends dafny.CodePoint> anchor)
  {
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((rels).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
      } else if ((((((RelDecl)(java.lang.Object)((rels).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_rel()).equals(rel)) && (((((RelDecl)(java.lang.Object)((rels).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_anchor()).equals(anchor))) {
        return (((RelDecl)(java.lang.Object)((rels).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_members();
      } else {
        dafny.DafnySequence<? extends RelDecl> _in0 = (rels).drop(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.CodePoint> _in1 = rel;
        dafny.DafnySequence<? extends dafny.CodePoint> _in2 = anchor;
        rels = _in0;
        rel = _in1;
        anchor = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static ResPat ResolveSel(Ontology ont, ResSel s)
  {
    ResSel _source0 = s;
    if (_source0.is_Exact()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ResSel_Exact)_source0)._id;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_id = _0___mcc_h0;
      return ResPat.create_PSet(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), _1_id));
    } else if (_source0.is_OneOf()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _2___mcc_h1 = ((GoalIr.ResSel_OneOf)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_ids = _2___mcc_h1;
      return ResPat.create_PSet(_3_ids);
    } else if (_source0.is_Related()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalIr.ResSel_Related)_source0)._rel;
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.ResSel_Related)_source0)._anchor;
      dafny.DafnySequence<? extends dafny.CodePoint> _6_anchor = _5___mcc_h3;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_rel = _4___mcc_h2;
      return ResPat.create_PSet(__default.RelMembers((ont).dtor_rels(), _7_rel, _6_anchor));
    } else if (_source0.is_AnyRes()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _8___mcc_h4 = ((GoalIr.ResSel_AnyRes)_source0)._reason;
      return ResPat.create_PStar();
    } else {
      dafny.DafnySequence<? extends ResPart> _9___mcc_h5 = ((GoalIr.ResSel_AllOf)_source0)._parts;
      dafny.DafnySequence<? extends ResPart> _10_ps = _9___mcc_h5;
      return __default.ResolveParts(ont, _10_ps);
    }
  }
  public static ResPat ResolvePart(Ontology ont, ResPart p)
  {
    ResPart _source0 = p;
    if (_source0.is_PartExact()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ResPart_PartExact)_source0)._id;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_id = _0___mcc_h0;
      return ResPat.create_PSet(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), _1_id));
    } else if (_source0.is_PartOneOf()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _2___mcc_h1 = ((GoalIr.ResPart_PartOneOf)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_ids = _2___mcc_h1;
      return ResPat.create_PSet(_3_ids);
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalIr.ResPart_PartRelated)_source0)._rel;
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.ResPart_PartRelated)_source0)._anchor;
      dafny.DafnySequence<? extends dafny.CodePoint> _6_anchor = _5___mcc_h3;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_rel = _4___mcc_h2;
      return ResPat.create_PSet(__default.RelMembers((ont).dtor_rels(), _7_rel, _6_anchor));
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> FilterIn(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> a, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> b)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((a).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, (((b).contains(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((a).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((a).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)))));
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _in0 = (a).drop(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _in1 = b;
        a = _in0;
        b = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static ResPat InterPat(ResPat x, ResPat y)
  {
    ResPat _source0 = x;
    if (_source0.is_PStar()) {
      return y;
    } else {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.ResPat_PSet)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_a = _0___mcc_h0;
      ResPat _source1 = y;
      if (_source1.is_PStar()) {
        return x;
      } else {
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _2___mcc_h1 = ((GoalIr.ResPat_PSet)_source1)._ids;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_b = _2___mcc_h1;
        return ResPat.create_PSet(__default.FilterIn(_1_a, _3_b));
      }
    }
  }
  public static ResPat ResolveParts(Ontology ont, dafny.DafnySequence<? extends ResPart> ps)
  {
    if ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) {
      return ResPat.create_PStar();
    } else {
      return __default.InterPat(__default.ResolvePart(ont, ((ResPart)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))), __default.ResolveParts(ont, (ps).drop(java.math.BigInteger.ONE)));
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> VerbsOfClass(dafny.DafnySequence<? extends VerbDecl> vs, dafny.DafnySequence<? extends dafny.CodePoint> cls)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((vs).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, ((((((VerbDecl)(java.lang.Object)((vs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_cls()).equals(cls)) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((VerbDecl)(java.lang.Object)((vs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_verb())) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)))));
        dafny.DafnySequence<? extends VerbDecl> _in0 = (vs).drop(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.CodePoint> _in1 = cls;
        vs = _in0;
        cls = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static LSel ResolveBSel(Ontology ont, Sel s)
  {
    Sel _source0 = s;
    if (_source0.is_SelGids()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.Sel_SelGids)_source0)._gids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_g = _0___mcc_h0;
      return LSel.create(_1_g, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.Sel_SelEffect)_source0)._cls;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_c = _2___mcc_h1;
      return LSel.create(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), __default.VerbsOfClass((ont).dtor_verbs(), _3_c));
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> ProhVerbs(Ontology ont, ProhTarget t)
  {
    ProhTarget _source0 = t;
    if (_source0.is_PVerb()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ProhTarget_PVerb)_source0)._verb;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_v = _0___mcc_h0;
      return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), _1_v);
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.ProhTarget_PEffect)_source0)._cls;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_c = _2___mcc_h1;
      return __default.VerbsOfClass((ont).dtor_verbs(), _3_c);
    }
  }
  public static java.math.BigInteger EqT(V x, V y)
  {
    V _source0 = x;
    if (_source0.is_VQ()) {
      Q _0___mcc_h0 = ((GoalIr.V_VQ)_source0)._q;
      Q _1_p = _0___mcc_h0;
      V _source1 = y;
      if (_source1.is_VQ()) {
        Q _2___mcc_h3 = ((GoalIr.V_VQ)_source1)._q;
        Q _3_q = _2___mcc_h3;
        if (java.util.Objects.equals((_1_p).dtor_u(), (_3_q).dtor_u())) {
          return __default.B2T(java.util.Objects.equals((_1_p).dtor_n(), (_3_q).dtor_n()));
        } else {
          return __default.KU();
        }
      } else if (_source1.is_VS()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h5 = ((GoalIr.V_VS)_source1)._s;
        return __default.KU();
      } else {
        dafny.DafnySequence<? extends Atom> _5___mcc_h7 = ((GoalIr.V_VSet)_source1)._items;
        return __default.KU();
      }
    } else if (_source0.is_VS()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _6___mcc_h1 = ((GoalIr.V_VS)_source0)._s;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_s = _6___mcc_h1;
      V _source2 = y;
      if (_source2.is_VQ()) {
        Q _8___mcc_h9 = ((GoalIr.V_VQ)_source2)._q;
        return __default.KU();
      } else if (_source2.is_VS()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _9___mcc_h11 = ((GoalIr.V_VS)_source2)._s;
        dafny.DafnySequence<? extends dafny.CodePoint> _10_t = _9___mcc_h11;
        return __default.B2T((_7_s).equals(_10_t));
      } else {
        dafny.DafnySequence<? extends Atom> _11___mcc_h13 = ((GoalIr.V_VSet)_source2)._items;
        return __default.KU();
      }
    } else {
      dafny.DafnySequence<? extends Atom> _12___mcc_h2 = ((GoalIr.V_VSet)_source0)._items;
      return __default.KU();
    }
  }
  public static java.math.BigInteger LtT(V x, V y)
  {
    V _source0 = x;
    if (_source0.is_VQ()) {
      Q _0___mcc_h0 = ((GoalIr.V_VQ)_source0)._q;
      Q _1_p = _0___mcc_h0;
      V _source1 = y;
      if (_source1.is_VQ()) {
        Q _2___mcc_h6 = ((GoalIr.V_VQ)_source1)._q;
        Q _3_q = _2___mcc_h6;
        if (java.util.Objects.equals((_1_p).dtor_u(), (_3_q).dtor_u())) {
          return __default.B2T(((_1_p).dtor_n()).compareTo((_3_q).dtor_n()) < 0);
        } else {
          return __default.KU();
        }
      } else if (_source1.is_VS()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h8 = ((GoalIr.V_VS)_source1)._s;
        return __default.KU();
      } else {
        dafny.DafnySequence<? extends Atom> _5___mcc_h10 = ((GoalIr.V_VSet)_source1)._items;
        return __default.KU();
      }
    } else if (_source0.is_VS()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _6___mcc_h2 = ((GoalIr.V_VS)_source0)._s;
      return __default.KU();
    } else {
      dafny.DafnySequence<? extends Atom> _7___mcc_h4 = ((GoalIr.V_VSet)_source0)._items;
      return __default.KU();
    }
  }
  public static java.math.BigInteger InT(V x, dafny.DafnySequence<? extends Atom> items)
  {
    if ((java.math.BigInteger.valueOf((items).length())).signum() == 0) {
      return __default.KF();
    } else {
      return __default.OrK(__default.EqT(x, __default.AtomV(((Atom)(java.lang.Object)((items).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))), __default.InT(x, (items).drop(java.math.BigInteger.ONE)));
    }
  }
  public static java.math.BigInteger CmpT(Op op, Option<V> x, Option<V> y)
  {
    Option<V> _pat_let_tv0 = x;
    if (((x).is_None()) || ((y).is_None())) {
      return __default.KU();
    } else {
      Op _source0 = op;
      if (_source0.is_Eq()) {
        return __default.EqT((x).dtor_v(), (y).dtor_v());
      } else if (_source0.is_Ne()) {
        return __default.NotK(__default.EqT((x).dtor_v(), (y).dtor_v()));
      } else if (_source0.is_Lt()) {
        return __default.LtT((x).dtor_v(), (y).dtor_v());
      } else if (_source0.is_Lte()) {
        return __default.NotK(__default.LtT((y).dtor_v(), (x).dtor_v()));
      } else if (_source0.is_Gt()) {
        return __default.LtT((y).dtor_v(), (x).dtor_v());
      } else if (_source0.is_Gte()) {
        return __default.NotK(__default.LtT((x).dtor_v(), (y).dtor_v()));
      } else if (_source0.is_In()) {
        V _source1 = (y).dtor_v();
        if (_source1.is_VQ()) {
          Q _0___mcc_h0 = ((GoalIr.V_VQ)_source1)._q;
          return __default.KU();
        } else if (_source1.is_VS()) {
          dafny.DafnySequence<? extends dafny.CodePoint> _1___mcc_h2 = ((GoalIr.V_VS)_source1)._s;
          return __default.KU();
        } else {
          dafny.DafnySequence<? extends Atom> _2___mcc_h4 = ((GoalIr.V_VSet)_source1)._items;
          dafny.DafnySequence<? extends Atom> _3_items = _2___mcc_h4;
          return __default.InT((x).dtor_v(), _3_items);
        }
      } else {
        return __default.NotK(((java.util.function.Function<V, java.math.BigInteger>)(_source2_boxed0) -> {
          V _source2 = ((V)(java.lang.Object)(_source2_boxed0));
          if (_source2.is_VQ()) {
            Q _4___mcc_h6 = ((GoalIr.V_VQ)_source2)._q;
            return __default.KU();
          } else if (_source2.is_VS()) {
            dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h8 = ((GoalIr.V_VS)_source2)._s;
            return __default.KU();
          } else {
            dafny.DafnySequence<? extends Atom> _6___mcc_h10 = ((GoalIr.V_VSet)_source2)._items;
            dafny.DafnySequence<? extends Atom> _7_items = _6___mcc_h10;
            return __default.InT((_pat_let_tv0).dtor_v(), _7_items);
          }
        }).apply((y).dtor_v()));
      }
    }
  }
  public static Op NegOp(Op op) {
    Op _source0 = op;
    if (_source0.is_Eq()) {
      return Op.create_Ne();
    } else if (_source0.is_Ne()) {
      return Op.create_Eq();
    } else if (_source0.is_Lt()) {
      return Op.create_Gte();
    } else if (_source0.is_Lte()) {
      return Op.create_Gt();
    } else if (_source0.is_Gt()) {
      return Op.create_Lte();
    } else if (_source0.is_Gte()) {
      return Op.create_Lt();
    } else if (_source0.is_In()) {
      return Op.create_Nin();
    } else {
      return Op.create_In();
    }
  }
  public static Option<V> EvalT(Term t, Act a, Hist h)
  {
    Term _source0 = t;
    if (_source0.is_Param()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.Term_Param)_source0)._path;
      Ty _1___mcc_h1 = ((GoalIr.Term_Param)_source0)._ty;
      dafny.DafnySequence<? extends dafny.CodePoint> _2_p = _0___mcc_h0;
      if (((a).dtor_params()).<dafny.DafnySequence<? extends dafny.CodePoint>>contains(_2_p)) {
        return Option.<V>create_Some(V._typeDescriptor(), ((V)(java.lang.Object)(((a).dtor_params()).get(_2_p))));
      } else {
        return Option.<V>create_None(V._typeDescriptor());
      }
    } else if (_source0.is_Lit()) {
      V _3___mcc_h2 = ((GoalIr.Term_Lit)_source0)._v;
      V _4_v = _3___mcc_h2;
      return Option.<V>create_Some(V._typeDescriptor(), _4_v);
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.Term_HistAgg)_source0)._bid;
      Unit _6___mcc_h4 = ((GoalIr.Term_HistAgg)_source0)._u;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_b = _5___mcc_h3;
      if (((h).dtor_aggs()).<dafny.DafnySequence<? extends dafny.CodePoint>>contains(_7_b)) {
        return Option.<V>create_Some(V._typeDescriptor(), V.create_VQ(((Q)(java.lang.Object)(((h).dtor_aggs()).get(_7_b)))));
      } else {
        return Option.<V>create_None(V._typeDescriptor());
      }
    }
  }
  public static java.math.BigInteger EvalC(Cond c, Act a, Hist h)
  {
    Cond _source0 = c;
    if (_source0.is_CTrue()) {
      return __default.KT();
    } else if (_source0.is_Cmp()) {
      Op _0___mcc_h0 = ((GoalIr.Cond_Cmp)_source0)._op;
      Term _1___mcc_h1 = ((GoalIr.Cond_Cmp)_source0)._l;
      Term _2___mcc_h2 = ((GoalIr.Cond_Cmp)_source0)._r;
      Term _3_r = _2___mcc_h2;
      Term _4_l = _1___mcc_h1;
      Op _5_op = _0___mcc_h0;
      return __default.CmpT(_5_op, __default.EvalT(_4_l, a, h), __default.EvalT(_3_r, a, h));
    } else if (_source0.is_And()) {
      Cond _6___mcc_h3 = ((GoalIr.Cond_And)_source0)._a;
      Cond _7___mcc_h4 = ((GoalIr.Cond_And)_source0)._b;
      Cond _8_y = _7___mcc_h4;
      Cond _9_x = _6___mcc_h3;
      return __default.AndK(__default.EvalC(_9_x, a, h), __default.EvalC(_8_y, a, h));
    } else if (_source0.is_Or()) {
      Cond _10___mcc_h5 = ((GoalIr.Cond_Or)_source0)._a;
      Cond _11___mcc_h6 = ((GoalIr.Cond_Or)_source0)._b;
      Cond _12_y = _11___mcc_h6;
      Cond _13_x = _10___mcc_h5;
      return __default.OrK(__default.EvalC(_13_x, a, h), __default.EvalC(_12_y, a, h));
    } else {
      Cond _14___mcc_h7 = ((GoalIr.Cond_Not)_source0)._c;
      Cond _15_x = _14___mcc_h7;
      return __default.NotK(__default.EvalC(_15_x, a, h));
    }
  }
  public static boolean StrIn(dafny.DafnySequence<? extends dafny.CodePoint> x, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> s)
  {
    return (s).contains(x);
  }
  public static boolean AppliesL(LSel s, dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb)
  {
    return (((s).dtor_gids()).contains(gid)) || (((s).dtor_verbs()).contains(verb));
  }
  public static boolean InScope(Scope sc, Act a, Act x)
  {
    Scope _source0 = sc;
    if (_source0.is_SSession()) {
      return ((a).dtor_sess()).equals((x).dtor_sess());
    } else if (_source0.is_SPrincipal()) {
      return ((a).dtor_prin()).equals((x).dtor_prin());
    } else if (_source0.is_SOrg()) {
      return ((a).dtor_org()).equals((x).dtor_org());
    } else {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.Scope_SFleet)_source0)._agents;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_ag = _0___mcc_h0;
      return ((_1_ag).contains((a).dtor_agent())) && ((_1_ag).contains((x).dtor_agent()));
    }
  }
  public static boolean InWindow(Window w, Act a, Act x)
  {
    Window _source0 = w;
    if (_source0.is_WTask()) {
      return true;
    } else if (_source0.is_WSliding()) {
      java.math.BigInteger _0___mcc_h0 = ((GoalIr.Window_WSliding)_source0)._ms;
      java.math.BigInteger _1_ms = _0___mcc_h0;
      return (((x).dtor_t()).compareTo(((a).dtor_t()).subtract(_1_ms)) > 0) && (((x).dtor_t()).compareTo((a).dtor_t()) <= 0);
    } else if (_source0.is_WPeriod()) {
      java.math.BigInteger _2___mcc_h1 = ((GoalIr.Window_WPeriod)_source0)._ms;
      java.math.BigInteger _3___mcc_h2 = ((GoalIr.Window_WPeriod)_source0)._t0;
      java.math.BigInteger _4_t0 = _3___mcc_h2;
      java.math.BigInteger _5_ms = _2___mcc_h1;
      return ((_5_ms).signum() == 1) && (java.util.Objects.equals(dafny.DafnyEuclidean.EuclideanDivision(((a).dtor_t()).subtract(_4_t0), _5_ms), dafny.DafnyEuclidean.EuclideanDivision(((x).dtor_t()).subtract(_4_t0), _5_ms)));
    } else {
      return true;
    }
  }
  public static dafny.DafnySequence<? extends Act> SelItems(BCore core, LSel s, dafny.DafnySequence<? extends Adm> adms, Act a)
  {
    dafny.DafnySequence<? extends Act> _0___accumulator = dafny.DafnySequence.<Act> empty(Act._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((adms).length())).signum() == 0) {
        return dafny.DafnySequence.<Act>concatenate(_0___accumulator, dafny.DafnySequence.<Act> of(Act._typeDescriptor(), a));
      } else {
        _0___accumulator = dafny.DafnySequence.<Act>concatenate(_0___accumulator, ((((__default.AppliesL(s, (((Adm)(java.lang.Object)((adms).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_gid(), ((((Adm)(java.lang.Object)((adms).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_act()).dtor_verb())) && (__default.InScope((core).dtor_scope(), a, (((Adm)(java.lang.Object)((adms).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_act()))) && (__default.InWindow((core).dtor_window(), a, (((Adm)(java.lang.Object)((adms).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_act()))) ? (dafny.DafnySequence.<Act> of(Act._typeDescriptor(), (((Adm)(java.lang.Object)((adms).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_act())) : (dafny.DafnySequence.<Act> empty(Act._typeDescriptor()))));
        BCore _in0 = core;
        LSel _in1 = s;
        dafny.DafnySequence<? extends Adm> _in2 = (adms).drop(java.math.BigInteger.ONE);
        Act _in3 = a;
        core = _in0;
        s = _in1;
        adms = _in2;
        a = _in3;
        continue TAIL_CALL_START;
      }
    }
  }
  public static Option<dafny.DafnySequence<? extends java.math.BigInteger>> ItemVals(BCore core, dafny.DafnySequence<? extends Act> items, Hist h)
  {
    if ((java.math.BigInteger.valueOf((items).length())).signum() == 0) {
      return Option.<dafny.DafnySequence<? extends java.math.BigInteger>>create_Some(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER), dafny.DafnySequence.<java.math.BigInteger> empty(dafny.TypeDescriptor.BIG_INTEGER));
    } else {
      Option<V> _source0 = __default.EvalT((core).dtor_value(), ((Act)(java.lang.Object)((items).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), h);
      if (_source0.is_None()) {
        return Option.<dafny.DafnySequence<? extends java.math.BigInteger>>create_None(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER));
      } else {
        V _0___mcc_h0 = ((GoalIr.Option_Some<V>)_source0)._v;
        V _source1 = _0___mcc_h0;
        if (_source1.is_VQ()) {
          Q _1___mcc_h2 = ((GoalIr.V_VQ)_source1)._q;
          Q _2_q = _1___mcc_h2;
          if (!java.util.Objects.equals((_2_q).dtor_u(), ((core).dtor_cap()).dtor_u())) {
            return Option.<dafny.DafnySequence<? extends java.math.BigInteger>>create_None(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER));
          } else {
            Option<dafny.DafnySequence<? extends java.math.BigInteger>> _source2 = __default.ItemVals(core, (items).drop(java.math.BigInteger.ONE), h);
            if (_source2.is_None()) {
              return Option.<dafny.DafnySequence<? extends java.math.BigInteger>>create_None(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER));
            } else {
              dafny.DafnySequence<? extends java.math.BigInteger> _3___mcc_h8 = ((GoalIr.Option_Some<dafny.DafnySequence<? extends java.math.BigInteger>>)_source2)._v;
              dafny.DafnySequence<? extends java.math.BigInteger> _4_r = _3___mcc_h8;
              return Option.<dafny.DafnySequence<? extends java.math.BigInteger>>create_Some(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER), dafny.DafnySequence.<java.math.BigInteger>concatenate(dafny.DafnySequence.<java.math.BigInteger> of(dafny.TypeDescriptor.BIG_INTEGER, (_2_q).dtor_n()), _4_r));
            }
          }
        } else if (_source1.is_VS()) {
          dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h4 = ((GoalIr.V_VS)_source1)._s;
          return Option.<dafny.DafnySequence<? extends java.math.BigInteger>>create_None(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER));
        } else {
          dafny.DafnySequence<? extends Atom> _6___mcc_h6 = ((GoalIr.V_VSet)_source1)._items;
          return Option.<dafny.DafnySequence<? extends java.math.BigInteger>>create_None(dafny.DafnySequence.<java.math.BigInteger>_typeDescriptor(dafny.TypeDescriptor.BIG_INTEGER));
        }
      }
    }
  }
  public static java.math.BigInteger SumI(dafny.DafnySequence<? extends java.math.BigInteger> xs) {
    java.math.BigInteger _0___accumulator = java.math.BigInteger.ZERO;
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return (java.math.BigInteger.ZERO).add(_0___accumulator);
      } else {
        _0___accumulator = (_0___accumulator).add(((java.math.BigInteger)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))));
        dafny.DafnySequence<? extends java.math.BigInteger> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static java.math.BigInteger MaxI(dafny.DafnySequence<? extends java.math.BigInteger> xs) {
    if (java.util.Objects.equals(java.math.BigInteger.valueOf((xs).length()), java.math.BigInteger.ONE)) {
      return ((java.math.BigInteger)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))));
    } else {
      java.math.BigInteger _0_m = __default.MaxI((xs).drop(java.math.BigInteger.ONE));
      if ((((java.math.BigInteger)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).compareTo(_0_m) >= 0) {
        return ((java.math.BigInteger)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))));
      } else {
        return _0_m;
      }
    }
  }
  public static Option<dafny.DafnySequence<? extends V>> KeyVals(BCore core, dafny.DafnySequence<? extends Act> items)
  {
    if ((java.math.BigInteger.valueOf((items).length())).signum() == 0) {
      return Option.<dafny.DafnySequence<? extends V>>create_Some(dafny.DafnySequence.<V>_typeDescriptor(V._typeDescriptor()), dafny.DafnySequence.<V> empty(V._typeDescriptor()));
    } else if (!((((Act)(java.lang.Object)((items).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_params()).<dafny.DafnySequence<? extends dafny.CodePoint>>contains((core).dtor_key())) {
      return Option.<dafny.DafnySequence<? extends V>>create_None(dafny.DafnySequence.<V>_typeDescriptor(V._typeDescriptor()));
    } else {
      Option<dafny.DafnySequence<? extends V>> _source0 = __default.KeyVals(core, (items).drop(java.math.BigInteger.ONE));
      if (_source0.is_None()) {
        return Option.<dafny.DafnySequence<? extends V>>create_None(dafny.DafnySequence.<V>_typeDescriptor(V._typeDescriptor()));
      } else {
        dafny.DafnySequence<? extends V> _0___mcc_h0 = ((GoalIr.Option_Some<dafny.DafnySequence<? extends V>>)_source0)._v;
        dafny.DafnySequence<? extends V> _1_r = _0___mcc_h0;
        return Option.<dafny.DafnySequence<? extends V>>create_Some(dafny.DafnySequence.<V>_typeDescriptor(V._typeDescriptor()), dafny.DafnySequence.<V>concatenate(dafny.DafnySequence.<V> of(V._typeDescriptor(), ((V)(java.lang.Object)(((((Act)(java.lang.Object)((items).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_params()).get((core).dtor_key())))), _1_r));
      }
    }
  }
  public static dafny.DafnySequence<? extends V> Dedup(dafny.DafnySequence<? extends V> vs) {
    dafny.DafnySequence<? extends V> _0___accumulator = dafny.DafnySequence.<V> empty(V._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((vs).length())).signum() == 0) {
        return dafny.DafnySequence.<V>concatenate(_0___accumulator, dafny.DafnySequence.<V> empty(V._typeDescriptor()));
      } else if (((vs).drop(java.math.BigInteger.ONE)).contains(((V)(java.lang.Object)((vs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) {
        dafny.DafnySequence<? extends V> _in0 = (vs).drop(java.math.BigInteger.ONE);
        vs = _in0;
        continue TAIL_CALL_START;
      } else {
        _0___accumulator = dafny.DafnySequence.<V>concatenate(_0___accumulator, dafny.DafnySequence.<V> of(V._typeDescriptor(), ((V)(java.lang.Object)((vs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends V> _in1 = (vs).drop(java.math.BigInteger.ONE);
        vs = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static java.math.BigInteger Exceeded(BCore core, dafny.DafnySequence<? extends Act> items, Hist h)
  {
    Agg _source0 = (core).dtor_agg();
    if (_source0.is_ACount()) {
      return __default.B2T((java.math.BigInteger.valueOf((items).length())).compareTo(((core).dtor_cap()).dtor_n()) > 0);
    } else if (_source0.is_ASum()) {
      Option<dafny.DafnySequence<? extends java.math.BigInteger>> _source1 = __default.ItemVals(core, items, h);
      if (_source1.is_None()) {
        return __default.KU();
      } else {
        dafny.DafnySequence<? extends java.math.BigInteger> _0___mcc_h0 = ((GoalIr.Option_Some<dafny.DafnySequence<? extends java.math.BigInteger>>)_source1)._v;
        dafny.DafnySequence<? extends java.math.BigInteger> _1_xs = _0___mcc_h0;
        return __default.B2T((__default.SumI(_1_xs)).compareTo(((core).dtor_cap()).dtor_n()) > 0);
      }
    } else if (_source0.is_AMax()) {
      Option<dafny.DafnySequence<? extends java.math.BigInteger>> _source2 = __default.ItemVals(core, items, h);
      if (_source2.is_None()) {
        return __default.KU();
      } else {
        dafny.DafnySequence<? extends java.math.BigInteger> _2___mcc_h1 = ((GoalIr.Option_Some<dafny.DafnySequence<? extends java.math.BigInteger>>)_source2)._v;
        dafny.DafnySequence<? extends java.math.BigInteger> _3_xs = _2___mcc_h1;
        if ((java.math.BigInteger.valueOf((_3_xs).length())).signum() == 0) {
          return __default.KU();
        } else {
          return __default.B2T((__default.MaxI(_3_xs)).compareTo(((core).dtor_cap()).dtor_n()) > 0);
        }
      }
    } else {
      Option<dafny.DafnySequence<? extends V>> _source3 = __default.KeyVals(core, items);
      if (_source3.is_None()) {
        return __default.KU();
      } else {
        dafny.DafnySequence<? extends V> _4___mcc_h2 = ((GoalIr.Option_Some<dafny.DafnySequence<? extends V>>)_source3)._v;
        dafny.DafnySequence<? extends V> _5_vs = _4___mcc_h2;
        return __default.B2T((java.math.BigInteger.valueOf((__default.Dedup(_5_vs)).length())).compareTo(((core).dtor_cap()).dtor_n()) > 0);
      }
    }
  }
  public static java.math.BigInteger BoundStat(BCore core, LSel s, Act a, Hist h)
  {
    java.math.BigInteger _0_e = __default.Exceeded(core, __default.SelItems(core, s, (h).dtor_adms(), a), h);
    if (java.util.Objects.equals(_0_e, __default.KT())) {
      OnExceed _source0 = (core).dtor_onExceed();
      if (_source0.is_OnDeny()) {
        return __default.Deny();
      } else {
        return __default.Escalate();
      }
    } else if (java.util.Objects.equals(_0_e, __default.KU())) {
      return __default.Escalate();
    } else {
      return __default.Allow();
    }
  }
  public static java.math.BigInteger ValidityDec(Validity v, Delegation dg, Act a, Hist h)
  {
    if ((((a).dtor_t()).compareTo((v).dtor_notBefore()) < 0) || (((a).dtor_t()).compareTo((v).dtor_notAfter()) > 0)) {
      return __default.Deny();
    } else if (((((v).dtor_maxIdle()).signum() == 1) && (((h).dtor_last()).signum() != -1)) && ((((a).dtor_t()).subtract((h).dtor_last())).compareTo((v).dtor_maxIdle()) > 0)) {
      return __default.Deny();
    } else if ((((a).dtor_depth()).signum() == -1) || (((a).dtor_depth()).compareTo((dg).dtor_maxDepth()) > 0)) {
      return __default.Deny();
    } else {
      return __default.Allow();
    }
  }
  public static boolean DelegOk(Delegation dg, dafny.DafnySequence<? extends dafny.CodePoint> gid, Act a)
  {
    return (((a).dtor_depth()).signum() == 0) || (((dg).dtor_mayTouch()).contains(gid));
  }
  public static java.math.BigInteger ProhOne(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs, ResPat res, Cond c, Act a, Hist h)
  {
    java.math.BigInteger _0_m = __default.AndK(__default.B2T((verbs).contains((a).dtor_verb())), __default.AndK(__default.B2T(__default.ResOk(res, (a).dtor_res())), __default.EvalC(c, a, h)));
    if (java.util.Objects.equals(_0_m, __default.KT())) {
      return __default.Deny();
    } else if (java.util.Objects.equals(_0_m, __default.KU())) {
      return __default.Escalate();
    } else {
      return __default.Allow();
    }
  }
  public static java.math.BigInteger ProhDecG(Ontology ont, dafny.DafnySequence<? extends Prohibit> ps, Act a, Hist h)
  {
    if ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) {
      return __default.Allow();
    } else {
      return __default.MeetD(__default.ProhOne(__default.ProhVerbs(ont, (((Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_target()), __default.ResolveSel(ont, (((Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_res()), (((Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_cond(), a, h), __default.ProhDecG(ont, (ps).drop(java.math.BigInteger.ONE), a, h));
    }
  }
  public static java.math.BigInteger EscOne(java.math.BigInteger m) {
    if (java.util.Objects.equals(m, __default.KF())) {
      return __default.Allow();
    } else {
      return __default.Escalate();
    }
  }
  public static java.math.BigInteger EscDecG(dafny.DafnySequence<? extends Cond> cs, Act a, Hist h)
  {
    if ((java.math.BigInteger.valueOf((cs).length())).signum() == 0) {
      return __default.Allow();
    } else {
      return __default.MeetD(__default.EscOne(__default.EvalC(((Cond)(java.lang.Object)((cs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), a, h)), __default.EscDecG((cs).drop(java.math.BigInteger.ONE), a, h));
    }
  }
  public static java.math.BigInteger BoundsDecG(Ontology ont, dafny.DafnySequence<? extends Bound> bs, dafny.DafnySequence<? extends dafny.CodePoint> gid, Act a, Hist h)
  {
    if ((java.math.BigInteger.valueOf((bs).length())).signum() == 0) {
      return __default.Allow();
    } else {
      LSel _0_s = __default.ResolveBSel(ont, (((Bound)(java.lang.Object)((bs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_sel());
      return __default.MeetD(((__default.AppliesL(_0_s, gid, (a).dtor_verb())) ? (__default.BoundStat((((Bound)(java.lang.Object)((bs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_core(), _0_s, a, h)) : (__default.Allow())), __default.BoundsDecG(ont, (bs).drop(java.math.BigInteger.ONE), gid, a, h));
    }
  }
  public static java.math.BigInteger GrantMatch(Ontology ont, Grant g, Delegation dg, Act a, Hist h)
  {
    return __default.AndK(__default.B2T((((a).dtor_verb()).equals((g).dtor_verb())) && (__default.DelegOk(dg, (g).dtor_gid(), a))), __default.AndK(__default.B2T(__default.ResOk(__default.ResolveSel(ont, (g).dtor_res()), (a).dtor_res())), __default.EvalC((g).dtor_cond(), a, h)));
  }
  public static java.math.BigInteger GrantDecG(Ontology ont, Goal g, Grant gr, Act a, Hist h)
  {
    return __default.MeetD(__default.DecOfTri(__default.GrantMatch(ont, gr, (g).dtor_deleg(), a, h)), __default.BoundsDecG(ont, (g).dtor_bounds(), (gr).dtor_gid(), a, h));
  }
  public static java.math.BigInteger GrantsDecG(Ontology ont, Goal g, dafny.DafnySequence<? extends Grant> gs, Act a, Hist h)
  {
    if ((java.math.BigInteger.valueOf((gs).length())).signum() == 0) {
      return __default.Deny();
    } else {
      return __default.JoinD(__default.GrantDecG(ont, g, ((Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), a, h), __default.GrantsDecG(ont, g, (gs).drop(java.math.BigInteger.ONE), a, h));
    }
  }
  public static java.math.BigInteger DG(Ontology ont, Goal g, Act a, Hist h)
  {
    return __default.MeetD(__default.ValidityDec((g).dtor_validity(), (g).dtor_deleg(), a, h), __default.MeetD(__default.ProhDecG(ont, (g).dtor_prohibits(), a, h), __default.MeetD(__default.EscDecG((g).dtor_escalateOn(), a, h), __default.GrantsDecG(ont, g, (g).dtor_grants(), a, h))));
  }
  public static boolean StrLt(dafny.DafnySequence<? extends dafny.CodePoint> a, dafny.DafnySequence<? extends dafny.CodePoint> b)
  {
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((b).length())).signum() == 0) {
        return false;
      } else if ((java.math.BigInteger.valueOf((a).length())).signum() == 0) {
        return true;
      } else if ((((dafny.CodePoint)((a).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))).value()) != (((dafny.CodePoint)((b).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))).value())) {
        return (java.math.BigInteger.valueOf(((dafny.CodePoint)((a).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))).value())).compareTo(java.math.BigInteger.valueOf(((dafny.CodePoint)((b).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))).value())) < 0;
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _in0 = (a).drop(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.CodePoint> _in1 = (b).drop(java.math.BigInteger.ONE);
        a = _in0;
        b = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static boolean StrictlySorted(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> xs) {
    return ((java.math.BigInteger.valueOf((xs).length())).compareTo(java.math.BigInteger.ONE) <= 0) || ((__default.StrLt(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ONE))))))) && (__default.StrictlySorted((xs).drop(java.math.BigInteger.ONE))));
  }
  public static boolean UnitOk(Unit u) {
    Unit _source0 = u;
    if (_source0.is_UMoney()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.Unit_UMoney)_source0)._ccy;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_c = _0___mcc_h0;
      return (java.math.BigInteger.valueOf((_1_c).length())).signum() == 1;
    } else if (_source0.is_UCount()) {
      return true;
    } else if (_source0.is_UDuration()) {
      return true;
    } else if (_source0.is_UInstant()) {
      return true;
    } else if (_source0.is_UBytes()) {
      return true;
    } else {
      return true;
    }
  }
  public static boolean TyOk(Ty t) {
    Ty _source0 = t;
    if (_source0.is_TyQ()) {
      Unit _0___mcc_h0 = ((GoalIr.Ty_TyQ)_source0)._u;
      Unit _1_u = _0___mcc_h0;
      return __default.UnitOk(_1_u);
    } else {
      return true;
    }
  }
  public static boolean VOk(V v) {
    V _source0 = v;
    if (_source0.is_VQ()) {
      Q _0___mcc_h0 = ((GoalIr.V_VQ)_source0)._q;
      Q _1_q = _0___mcc_h0;
      return __default.UnitOk((_1_q).dtor_u());
    } else if (_source0.is_VS()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.V_VS)_source0)._s;
      return true;
    } else {
      dafny.DafnySequence<? extends Atom> _3___mcc_h2 = ((GoalIr.V_VSet)_source0)._items;
      dafny.DafnySequence<? extends Atom> _4_items = _3___mcc_h2;
      return ((java.util.function.Function<dafny.DafnySequence<? extends Atom>, Boolean>)(_5_items) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_5_items).length())), true, ((_forall_var_0_boxed0) -> {
        java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
        java.math.BigInteger _6_i = (java.math.BigInteger)_forall_var_0;
        return !(((_6_i).signum() != -1) && ((_6_i).compareTo(java.math.BigInteger.valueOf((_5_items).length())) < 0)) || (((java.util.function.Function<Atom, Boolean>)(_source1_boxed0) -> {
          Atom _source1 = ((Atom)(java.lang.Object)(_source1_boxed0));
          if (_source1.is_AQ()) {
            Q _7___mcc_h3 = ((GoalIr.Atom_AQ)_source1)._q;
            Q _8_q = _7___mcc_h3;
            return __default.UnitOk((_8_q).dtor_u());
          } else {
            dafny.DafnySequence<? extends dafny.CodePoint> _9___mcc_h4 = ((GoalIr.Atom_AS)_source1)._s;
            return true;
          }
        }).apply(((Atom)(java.lang.Object)((_5_items).select(dafny.Helpers.toInt((_6_i)))))));
      }));}).apply(_4_items);
    }
  }
  public static Option<Ty> TypeOfTerm(Term t) {
    Term _source0 = t;
    if (_source0.is_Param()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.Term_Param)_source0)._path;
      Ty _1___mcc_h1 = ((GoalIr.Term_Param)_source0)._ty;
      Ty _2_ty = _1___mcc_h1;
      return Option.<Ty>create_Some(Ty._typeDescriptor(), _2_ty);
    } else if (_source0.is_Lit()) {
      V _3___mcc_h2 = ((GoalIr.Term_Lit)_source0)._v;
      V _4_v = _3___mcc_h2;
      return __default.TypeOfV(_4_v);
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.Term_HistAgg)_source0)._bid;
      Unit _6___mcc_h4 = ((GoalIr.Term_HistAgg)_source0)._u;
      Unit _7_u = _6___mcc_h4;
      return Option.<Ty>create_Some(Ty._typeDescriptor(), Ty.create_TyQ(_7_u));
    }
  }
  public static boolean TermOk(Term t) {
    Term _source0 = t;
    if (_source0.is_Param()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.Term_Param)_source0)._path;
      Ty _1___mcc_h1 = ((GoalIr.Term_Param)_source0)._ty;
      Ty _2_ty = _1___mcc_h1;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_p = _0___mcc_h0;
      return ((java.math.BigInteger.valueOf((_3_p).length())).signum() == 1) && (__default.TyOk(_2_ty));
    } else if (_source0.is_Lit()) {
      V _4___mcc_h2 = ((GoalIr.Term_Lit)_source0)._v;
      V _5_v = _4___mcc_h2;
      return __default.VOk(_5_v);
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _6___mcc_h3 = ((GoalIr.Term_HistAgg)_source0)._bid;
      Unit _7___mcc_h4 = ((GoalIr.Term_HistAgg)_source0)._u;
      Unit _8_u = _7___mcc_h4;
      dafny.DafnySequence<? extends dafny.CodePoint> _9_b = _6___mcc_h3;
      return ((java.math.BigInteger.valueOf((_9_b).length())).signum() == 1) && (__default.UnitOk(_8_u));
    }
  }
  public static boolean AllOfTy(dafny.DafnySequence<? extends Atom> items, Ty ty)
  {
    return ((dafny.Function2<dafny.DafnySequence<? extends Atom>, Ty, Boolean>)(_0_items, _1_ty) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_items).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf((_0_items).length())) < 0)) || (java.util.Objects.equals(__default.TypeOfV(__default.AtomV(((Atom)(java.lang.Object)((_0_items).select(dafny.Helpers.toInt((_2_i))))))), Option.<Ty>create_Some(Ty._typeDescriptor(), _1_ty)));
    }));}).apply(items, ty);
  }
  public static boolean CmpTyped(Op op, Term l, Term r)
  {
    Term _pat_let_tv0 = l;
    Term _pat_let_tv1 = r;
    Term _pat_let_tv2 = l;
    Term _pat_let_tv3 = r;
    Term _pat_let_tv4 = l;
    Term _pat_let_tv5 = r;
    Term _pat_let_tv6 = l;
    Term _pat_let_tv7 = l;
    Term _pat_let_tv8 = r;
    Term _pat_let_tv9 = l;
    Term _pat_let_tv10 = l;
    Term _pat_let_tv11 = r;
    Term _pat_let_tv12 = l;
    Term _pat_let_tv13 = l;
    Term _pat_let_tv14 = r;
    Term _pat_let_tv15 = l;
    Term _pat_let_tv16 = r;
    Term _pat_let_tv17 = r;
    Term _pat_let_tv18 = r;
    Term _pat_let_tv19 = l;
    Term _pat_let_tv20 = r;
    Term _pat_let_tv21 = r;
    Term _pat_let_tv22 = r;
    Term _pat_let_tv23 = l;
    return (((__default.TermOk(l)) && (__default.TermOk(r))) && ((__default.TypeOfTerm(l)).is_Some())) && (((java.util.function.Function<Op, Boolean>)(_source0_boxed0) -> {
      Op _source0 = ((Op)(java.lang.Object)(_source0_boxed0));
      if (_source0.is_Eq()) {
        return java.util.Objects.equals(__default.TypeOfTerm(_pat_let_tv0), __default.TypeOfTerm(_pat_let_tv1));
      } else if (_source0.is_Ne()) {
        return java.util.Objects.equals(__default.TypeOfTerm(_pat_let_tv2), __default.TypeOfTerm(_pat_let_tv3));
      } else if (_source0.is_Lt()) {
        return (java.util.Objects.equals(__default.TypeOfTerm(_pat_let_tv4), __default.TypeOfTerm(_pat_let_tv5))) && (((__default.TypeOfTerm(_pat_let_tv6)).dtor_v()).is_TyQ());
      } else if (_source0.is_Lte()) {
        return (java.util.Objects.equals(__default.TypeOfTerm(_pat_let_tv7), __default.TypeOfTerm(_pat_let_tv8))) && (((__default.TypeOfTerm(_pat_let_tv9)).dtor_v()).is_TyQ());
      } else if (_source0.is_Gt()) {
        return (java.util.Objects.equals(__default.TypeOfTerm(_pat_let_tv10), __default.TypeOfTerm(_pat_let_tv11))) && (((__default.TypeOfTerm(_pat_let_tv12)).dtor_v()).is_TyQ());
      } else if (_source0.is_Gte()) {
        return (java.util.Objects.equals(__default.TypeOfTerm(_pat_let_tv13), __default.TypeOfTerm(_pat_let_tv14))) && (((__default.TypeOfTerm(_pat_let_tv15)).dtor_v()).is_TyQ());
      } else if (_source0.is_In()) {
        return (((_pat_let_tv16).is_Lit()) && (((_pat_let_tv17).dtor_v()).is_VSet())) && (__default.AllOfTy(((_pat_let_tv18).dtor_v()).dtor_items(), (__default.TypeOfTerm(_pat_let_tv19)).dtor_v()));
      } else {
        return (((_pat_let_tv20).is_Lit()) && (((_pat_let_tv21).dtor_v()).is_VSet())) && (__default.AllOfTy(((_pat_let_tv22).dtor_v()).dtor_items(), (__default.TypeOfTerm(_pat_let_tv23)).dtor_v()));
      }
    }).apply(op));
  }
  public static boolean CondTyped(Cond c, dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean> ok)
  {
    Cond _source0 = c;
    if (_source0.is_CTrue()) {
      return true;
    } else if (_source0.is_Cmp()) {
      Op _0___mcc_h0 = ((GoalIr.Cond_Cmp)_source0)._op;
      Term _1___mcc_h1 = ((GoalIr.Cond_Cmp)_source0)._l;
      Term _2___mcc_h2 = ((GoalIr.Cond_Cmp)_source0)._r;
      Term _3_r = _2___mcc_h2;
      Term _4_l = _1___mcc_h1;
      Op _5_op = _0___mcc_h0;
      return ((__default.CmpTyped(_5_op, _4_l, _3_r)) && (__default.ParamsOk(_4_l, ok))) && (__default.ParamsOk(_3_r, ok));
    } else if (_source0.is_And()) {
      Cond _6___mcc_h3 = ((GoalIr.Cond_And)_source0)._a;
      Cond _7___mcc_h4 = ((GoalIr.Cond_And)_source0)._b;
      Cond _8_y = _7___mcc_h4;
      Cond _9_x = _6___mcc_h3;
      return (__default.CondTyped(_9_x, ok)) && (__default.CondTyped(_8_y, ok));
    } else if (_source0.is_Or()) {
      Cond _10___mcc_h5 = ((GoalIr.Cond_Or)_source0)._a;
      Cond _11___mcc_h6 = ((GoalIr.Cond_Or)_source0)._b;
      Cond _12_y = _11___mcc_h6;
      Cond _13_x = _10___mcc_h5;
      return (__default.CondTyped(_13_x, ok)) && (__default.CondTyped(_12_y, ok));
    } else {
      Cond _14___mcc_h7 = ((GoalIr.Cond_Not)_source0)._c;
      Cond _15_x = _14___mcc_h7;
      return __default.CondTyped(_15_x, ok);
    }
  }
  public static boolean ParamsOk(Term t, dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean> ok)
  {
    Term _source0 = t;
    if (_source0.is_Param()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.Term_Param)_source0)._path;
      Ty _1___mcc_h1 = ((GoalIr.Term_Param)_source0)._ty;
      Ty _2_ty = _1___mcc_h1;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_p = _0___mcc_h0;
      return ((boolean)(java.lang.Object)((ok).apply(_3_p, _2_ty)));
    } else if (_source0.is_Lit()) {
      V _4___mcc_h4 = ((GoalIr.Term_Lit)_source0)._v;
      return true;
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h6 = ((GoalIr.Term_HistAgg)_source0)._bid;
      Unit _6___mcc_h7 = ((GoalIr.Term_HistAgg)_source0)._u;
      return true;
    }
  }
  public static Option<VerbDecl> FindDecl(dafny.DafnySequence<? extends VerbDecl> vs, dafny.DafnySequence<? extends dafny.CodePoint> verb)
  {
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((vs).length())).signum() == 0) {
        return Option.<VerbDecl>create_None(VerbDecl._typeDescriptor());
      } else if (((((VerbDecl)(java.lang.Object)((vs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_verb()).equals(verb)) {
        return Option.<VerbDecl>create_Some(VerbDecl._typeDescriptor(), ((VerbDecl)(java.lang.Object)((vs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))));
      } else {
        dafny.DafnySequence<? extends VerbDecl> _in0 = (vs).drop(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.CodePoint> _in1 = verb;
        vs = _in0;
        verb = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static boolean HasParam(dafny.DafnySequence<? extends ParamDecl> ps, dafny.DafnySequence<? extends dafny.CodePoint> p, Ty ty)
  {
    return (ps).contains(ParamDecl.create(p, ty));
  }
  public static boolean DeclaredFor(Ontology ont, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> verbs, dafny.DafnySequence<? extends dafny.CodePoint> p, Ty ty)
  {
    return ((dafny.Function4<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>, Ontology, dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean>)(_0_verbs, _1_ont, _2_p, _3_ty) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_verbs).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _4_i = (java.math.BigInteger)_forall_var_0;
      return !(((_4_i).signum() != -1) && ((_4_i).compareTo(java.math.BigInteger.valueOf((_0_verbs).length())) < 0)) || (((__default.FindDecl((_1_ont).dtor_verbs(), ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((_0_verbs).select(dafny.Helpers.toInt((_4_i))))))).is_Some()) && (__default.HasParam(((__default.FindDecl((_1_ont).dtor_verbs(), ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((_0_verbs).select(dafny.Helpers.toInt((_4_i))))))).dtor_v()).dtor_params(), _2_p, _3_ty)));
    }));}).apply(verbs, ont, p, ty);
  }
  public static boolean NoConflictP(dafny.DafnySequence<? extends ParamDecl> ps, dafny.DafnySequence<? extends dafny.CodePoint> p, Ty ty)
  {
    return ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) || (((!((((ParamDecl)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_path()).equals(p)) || (java.util.Objects.equals((((ParamDecl)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_ty(), ty))) && (__default.NoConflictP((ps).drop(java.math.BigInteger.ONE), p, ty)));
  }
  public static boolean NoConflict(dafny.DafnySequence<? extends VerbDecl> vs, dafny.DafnySequence<? extends dafny.CodePoint> p, Ty ty)
  {
    return ((java.math.BigInteger.valueOf((vs).length())).signum() == 0) || ((__default.NoConflictP((((VerbDecl)(java.lang.Object)((vs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_params(), p, ty)) && (__default.NoConflict((vs).drop(java.math.BigInteger.ONE), p, ty)));
  }
  public static boolean ResSelOk(Ontology ont, ResSel s)
  {
    ResSel _source0 = s;
    if (_source0.is_Exact()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ResSel_Exact)_source0)._id;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_id = _0___mcc_h0;
      return (java.math.BigInteger.valueOf((_1_id).length())).signum() == 1;
    } else if (_source0.is_OneOf()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _2___mcc_h1 = ((GoalIr.ResSel_OneOf)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_ids = _2___mcc_h1;
      return (java.math.BigInteger.valueOf((_3_ids).length())).signum() == 1;
    } else if (_source0.is_Related()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalIr.ResSel_Related)_source0)._rel;
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.ResSel_Related)_source0)._anchor;
      dafny.DafnySequence<? extends dafny.CodePoint> _6_anchor = _5___mcc_h3;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_rel = _4___mcc_h2;
      return ((dafny.Function3<Ontology, dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>, Boolean>)(_8_ont, _9_rel, _10_anchor) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_8_ont).dtor_rels()).length())), false, ((_exists_var_0_boxed0) -> {
        java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
        java.math.BigInteger _11_i = (java.math.BigInteger)_exists_var_0;
        return ((((_11_i).signum() != -1) && ((_11_i).compareTo(java.math.BigInteger.valueOf(((_8_ont).dtor_rels()).length())) < 0)) && (((((RelDecl)(java.lang.Object)(((_8_ont).dtor_rels()).select(dafny.Helpers.toInt((_11_i)))))).dtor_rel()).equals(_9_rel))) && (((((RelDecl)(java.lang.Object)(((_8_ont).dtor_rels()).select(dafny.Helpers.toInt((_11_i)))))).dtor_anchor()).equals(_10_anchor));
      }));}).apply(ont, _7_rel, _6_anchor);
    } else if (_source0.is_AnyRes()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _12___mcc_h4 = ((GoalIr.ResSel_AnyRes)_source0)._reason;
      return true;
    } else {
      dafny.DafnySequence<? extends ResPart> _13___mcc_h5 = ((GoalIr.ResSel_AllOf)_source0)._parts;
      dafny.DafnySequence<? extends ResPart> _14_ps = _13___mcc_h5;
      return ((java.math.BigInteger.valueOf((_14_ps).length())).compareTo(java.math.BigInteger.valueOf(2L)) >= 0) && (((dafny.Function2<dafny.DafnySequence<? extends ResPart>, Ontology, Boolean>)(_15_ps, _16_ont) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_15_ps).length())), true, ((_forall_var_0_boxed0) -> {
        java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
        java.math.BigInteger _17_i = (java.math.BigInteger)_forall_var_0;
        return !(((_17_i).signum() != -1) && ((_17_i).compareTo(java.math.BigInteger.valueOf((_15_ps).length())) < 0)) || (__default.PartOk(_16_ont, ((ResPart)(java.lang.Object)((_15_ps).select(dafny.Helpers.toInt((_17_i)))))));
      }));}).apply(_14_ps, ont));
    }
  }
  public static boolean PartOk(Ontology ont, ResPart p)
  {
    ResPart _source0 = p;
    if (_source0.is_PartExact()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ResPart_PartExact)_source0)._id;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_id = _0___mcc_h0;
      return (java.math.BigInteger.valueOf((_1_id).length())).signum() == 1;
    } else if (_source0.is_PartOneOf()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _2___mcc_h1 = ((GoalIr.ResPart_PartOneOf)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_ids = _2___mcc_h1;
      return (java.math.BigInteger.valueOf((_3_ids).length())).signum() == 1;
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalIr.ResPart_PartRelated)_source0)._rel;
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.ResPart_PartRelated)_source0)._anchor;
      dafny.DafnySequence<? extends dafny.CodePoint> _6_anchor = _5___mcc_h3;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_rel = _4___mcc_h2;
      return ((dafny.Function3<Ontology, dafny.DafnySequence<? extends dafny.CodePoint>, dafny.DafnySequence<? extends dafny.CodePoint>, Boolean>)(_8_ont, _9_rel, _10_anchor) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_8_ont).dtor_rels()).length())), false, ((_exists_var_0_boxed0) -> {
        java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
        java.math.BigInteger _11_i = (java.math.BigInteger)_exists_var_0;
        return ((((_11_i).signum() != -1) && ((_11_i).compareTo(java.math.BigInteger.valueOf(((_8_ont).dtor_rels()).length())) < 0)) && (((((RelDecl)(java.lang.Object)(((_8_ont).dtor_rels()).select(dafny.Helpers.toInt((_11_i)))))).dtor_rel()).equals(_9_rel))) && (((((RelDecl)(java.lang.Object)(((_8_ont).dtor_rels()).select(dafny.Helpers.toInt((_11_i)))))).dtor_anchor()).equals(_10_anchor));
      }));}).apply(ont, _7_rel, _6_anchor);
    }
  }
  public static boolean GrantOk(Ontology ont, Goal g, Grant gr)
  {
    return (((((java.math.BigInteger.valueOf(((gr).dtor_gid()).length())).signum() == 1) && ((__default.FindDecl((ont).dtor_verbs(), (gr).dtor_verb())).is_Some())) && (__default.ResSelOk(ont, (gr).dtor_res()))) && (!(((gr).dtor_res()).is_AnyRes()) || (((g).dtor_wildcardAck()).contains((gr).dtor_gid())))) && (__default.CondTyped((gr).dtor_cond(), ((dafny.Function2<Ontology, Grant, dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean>>)(_0_ont, _1_gr) -> {return ((dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean>)(_2_p_boxed0, _3_ty_boxed0) -> {
      dafny.DafnySequence<? extends dafny.CodePoint> _2_p = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(_2_p_boxed0));
      Ty _3_ty = ((Ty)(java.lang.Object)(_3_ty_boxed0));
      return __default.DeclaredFor(_0_ont, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (_1_gr).dtor_verb()), _2_p, _3_ty);
    });}).apply(ont, gr)));
  }
  public static boolean ProhibitOk(Ontology ont, Prohibit p)
  {
    Ontology _pat_let_tv0 = ont;
    Ontology _pat_let_tv1 = ont;
    return ((((java.math.BigInteger.valueOf(((p).dtor_pid()).length())).signum() == 1) && (__default.ResSelOk(ont, (p).dtor_res()))) && (((java.util.function.Function<ProhTarget, Boolean>)(_source0_boxed0) -> {
      ProhTarget _source0 = ((ProhTarget)(java.lang.Object)(_source0_boxed0));
      if (_source0.is_PVerb()) {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ProhTarget_PVerb)_source0)._verb;
        dafny.DafnySequence<? extends dafny.CodePoint> _1_v = _0___mcc_h0;
        return (__default.FindDecl((_pat_let_tv0).dtor_verbs(), _1_v)).is_Some();
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.ProhTarget_PEffect)_source0)._cls;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_c = _2___mcc_h1;
        return ((java.math.BigInteger.valueOf((_3_c).length())).signum() == 1) && ((java.math.BigInteger.valueOf((__default.VerbsOfClass((_pat_let_tv1).dtor_verbs(), _3_c)).length())).signum() == 1);
      }
    }).apply((p).dtor_target()))) && (__default.CondTyped((p).dtor_cond(), ((dafny.Function2<Ontology, Prohibit, dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean>>)(_4_ont, _5_p) -> {return ((dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean>)(_6_q_boxed0, _7_ty_boxed0) -> {
      dafny.DafnySequence<? extends dafny.CodePoint> _6_q = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(_6_q_boxed0));
      Ty _7_ty = ((Ty)(java.lang.Object)(_7_ty_boxed0));
      return __default.DeclaredFor(_4_ont, __default.ProhVerbs(_4_ont, (_5_p).dtor_target()), _6_q, _7_ty);
    });}).apply(ont, p)));
  }
  public static boolean WindowOk(Window w) {
    Window _source0 = w;
    if (_source0.is_WTask()) {
      return true;
    } else if (_source0.is_WSliding()) {
      java.math.BigInteger _0___mcc_h0 = ((GoalIr.Window_WSliding)_source0)._ms;
      java.math.BigInteger _1_ms = _0___mcc_h0;
      return (_1_ms).signum() == 1;
    } else if (_source0.is_WPeriod()) {
      java.math.BigInteger _2___mcc_h2 = ((GoalIr.Window_WPeriod)_source0)._ms;
      java.math.BigInteger _3___mcc_h3 = ((GoalIr.Window_WPeriod)_source0)._t0;
      java.math.BigInteger _4_ms = _2___mcc_h2;
      return (_4_ms).signum() == 1;
    } else {
      return true;
    }
  }
  public static boolean ScopeOk(Scope s) {
    Scope _source0 = s;
    if (_source0.is_SSession()) {
      return true;
    } else if (_source0.is_SPrincipal()) {
      return true;
    } else if (_source0.is_SOrg()) {
      return true;
    } else {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.Scope_SFleet)_source0)._agents;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_ag = _0___mcc_h0;
      return (java.math.BigInteger.valueOf((_1_ag).length())).signum() == 1;
    }
  }
  public static boolean BoundOk(Ontology ont, Goal g, Bound b)
  {
    Goal _pat_let_tv0 = g;
    Bound _pat_let_tv1 = b;
    Bound _pat_let_tv2 = b;
    Bound _pat_let_tv3 = b;
    Bound _pat_let_tv4 = b;
    Bound _pat_let_tv5 = b;
    Bound _pat_let_tv6 = b;
    Bound _pat_let_tv7 = b;
    return ((((((((java.math.BigInteger.valueOf(((b).dtor_bid()).length())).signum() == 1) && (__default.TermOk(((b).dtor_core()).dtor_value()))) && (__default.UnitOk((((b).dtor_core()).dtor_cap()).dtor_u()))) && (((((b).dtor_core()).dtor_cap()).dtor_n()).signum() != -1)) && (__default.WindowOk(((b).dtor_core()).dtor_window()))) && (__default.ScopeOk(((b).dtor_core()).dtor_scope()))) && (((java.util.function.Function<Sel, Boolean>)(_source0_boxed0) -> {
      Sel _source0 = ((Sel)(java.lang.Object)(_source0_boxed0));
      if (_source0.is_SelGids()) {
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.Sel_SelGids)_source0)._gids;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_gids = _0___mcc_h0;
        return ((java.math.BigInteger.valueOf((_1_gids).length())).signum() == 1) && (((dafny.Function2<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>, Goal, Boolean>)(_2_gids, _3_g) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_2_gids).length())), true, ((_forall_var_0_boxed0) -> {
          java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
          java.math.BigInteger _4_i = (java.math.BigInteger)_forall_var_0;
          return !(((_4_i).signum() != -1) && ((_4_i).compareTo(java.math.BigInteger.valueOf((_2_gids).length())) < 0)) || (((dafny.Function3<Goal, dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>, java.math.BigInteger, Boolean>)(_5_g, _6_gids, _7_i) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_5_g).dtor_grants()).length())), false, ((_exists_var_0_boxed0) -> {
            java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
            java.math.BigInteger _8_j = (java.math.BigInteger)_exists_var_0;
            return (((_8_j).signum() != -1) && ((_8_j).compareTo(java.math.BigInteger.valueOf(((_5_g).dtor_grants()).length())) < 0)) && (((((Grant)(java.lang.Object)(((_5_g).dtor_grants()).select(dafny.Helpers.toInt((_8_j)))))).dtor_gid()).equals(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((_6_gids).select(dafny.Helpers.toInt((_7_i)))))));
          }));}).apply(_3_g, _2_gids, _4_i));
        }));}).apply(_1_gids, _pat_let_tv0));
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _9___mcc_h1 = ((GoalIr.Sel_SelEffect)_source0)._cls;
        dafny.DafnySequence<? extends dafny.CodePoint> _10_c = _9___mcc_h1;
        return (java.math.BigInteger.valueOf((_10_c).length())).signum() == 1;
      }
    }).apply((b).dtor_sel()))) && (((java.util.function.Function<Agg, Boolean>)(_source1_boxed0) -> {
      Agg _source1 = ((Agg)(java.lang.Object)(_source1_boxed0));
      if (_source1.is_ACount()) {
        return java.util.Objects.equals((((_pat_let_tv1).dtor_core()).dtor_cap()).dtor_u(), Unit.create_UCount());
      } else if (_source1.is_ASum()) {
        return java.util.Objects.equals(__default.TypeOfTerm(((_pat_let_tv2).dtor_core()).dtor_value()), Option.<Ty>create_Some(Ty._typeDescriptor(), Ty.create_TyQ((((_pat_let_tv3).dtor_core()).dtor_cap()).dtor_u())));
      } else if (_source1.is_AMax()) {
        return java.util.Objects.equals(__default.TypeOfTerm(((_pat_let_tv4).dtor_core()).dtor_value()), Option.<Ty>create_Some(Ty._typeDescriptor(), Ty.create_TyQ((((_pat_let_tv5).dtor_core()).dtor_cap()).dtor_u())));
      } else {
        return (java.util.Objects.equals((((_pat_let_tv6).dtor_core()).dtor_cap()).dtor_u(), Unit.create_UCount())) && ((java.math.BigInteger.valueOf((((_pat_let_tv7).dtor_core()).dtor_key()).length())).signum() == 1);
      }
    }).apply(((b).dtor_core()).dtor_agg()));
  }
  public static boolean ValidityOk(Validity v, Delegation dg, Goal g)
  {
    return ((((((v).dtor_notBefore()).compareTo((v).dtor_notAfter()) <= 0) && (((v).dtor_maxIdle()).signum() != -1)) && ((((dg).dtor_maxDepth()).signum() != -1) && (((dg).dtor_maxDepth()).compareTo(java.math.BigInteger.valueOf(16L)) <= 0))) && ((dg).dtor_narrowOnly())) && (((dafny.Function2<Delegation, Goal, Boolean>)(_0_dg, _1_g) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_0_dg).dtor_mayTouch()).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf(((_0_dg).dtor_mayTouch()).length())) < 0)) || (((dafny.Function3<Goal, Delegation, java.math.BigInteger, Boolean>)(_3_g, _4_dg, _5_i) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_3_g).dtor_grants()).length())), false, ((_exists_var_0_boxed0) -> {
        java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
        java.math.BigInteger _6_j = (java.math.BigInteger)_exists_var_0;
        return (((_6_j).signum() != -1) && ((_6_j).compareTo(java.math.BigInteger.valueOf(((_3_g).dtor_grants()).length())) < 0)) && (((((Grant)(java.lang.Object)(((_3_g).dtor_grants()).select(dafny.Helpers.toInt((_6_j)))))).dtor_gid()).equals(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(((_4_dg).dtor_mayTouch()).select(dafny.Helpers.toInt((_5_i)))))));
      }));}).apply(_1_g, _0_dg, _2_i));
    }));}).apply(dg, g));
  }
  public static boolean HoleOk(Goal g, Hole h)
  {
    return ((java.math.BigInteger.valueOf(((h).dtor_hid()).length())).signum() == 1) && (((dafny.Function2<Hole, Goal, Boolean>)(_0_h, _1_g) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_0_h).dtor_affects()).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf(((_0_h).dtor_affects()).length())) < 0)) || (((dafny.Function3<Goal, Hole, java.math.BigInteger, Boolean>)(_3_g, _4_h, _5_i) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_3_g).dtor_grants()).length())), false, ((_exists_var_0_boxed0) -> {
        java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
        java.math.BigInteger _6_j = (java.math.BigInteger)_exists_var_0;
        return (((_6_j).signum() != -1) && ((_6_j).compareTo(java.math.BigInteger.valueOf(((_3_g).dtor_grants()).length())) < 0)) && (((((Grant)(java.lang.Object)(((_3_g).dtor_grants()).select(dafny.Helpers.toInt((_6_j)))))).dtor_gid()).equals(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(((_4_h).dtor_affects()).select(dafny.Helpers.toInt((_5_i)))))));
      }));}).apply(_1_g, _0_h, _2_i));
    }));}).apply(h, g));
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> Gids(dafny.DafnySequence<? extends Grant> gs) {
    return dafny.DafnySequence.Create(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), java.math.BigInteger.valueOf((gs).length()), ((java.util.function.Function<dafny.DafnySequence<? extends Grant>, java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>>)(_0_gs) -> {return ((java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return (((Grant)(java.lang.Object)((_0_gs).select(dafny.Helpers.toInt((_1_i)))))).dtor_gid();
    });}).apply(gs));
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> Pids(dafny.DafnySequence<? extends Prohibit> ps) {
    return dafny.DafnySequence.Create(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), java.math.BigInteger.valueOf((ps).length()), ((java.util.function.Function<dafny.DafnySequence<? extends Prohibit>, java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>>)(_0_ps) -> {return ((java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return (((Prohibit)(java.lang.Object)((_0_ps).select(dafny.Helpers.toInt((_1_i)))))).dtor_pid();
    });}).apply(ps));
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> Bids(dafny.DafnySequence<? extends Bound> bs) {
    return dafny.DafnySequence.Create(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), java.math.BigInteger.valueOf((bs).length()), ((java.util.function.Function<dafny.DafnySequence<? extends Bound>, java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>>)(_0_bs) -> {return ((java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return (((Bound)(java.lang.Object)((_0_bs).select(dafny.Helpers.toInt((_1_i)))))).dtor_bid();
    });}).apply(bs));
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> Hids(dafny.DafnySequence<? extends Hole> hs) {
    return dafny.DafnySequence.Create(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), java.math.BigInteger.valueOf((hs).length()), ((java.util.function.Function<dafny.DafnySequence<? extends Hole>, java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>>)(_0_hs) -> {return ((java.util.function.Function<java.math.BigInteger, dafny.DafnySequence<? extends dafny.CodePoint>>)(_1_i_boxed0) -> {
      java.math.BigInteger _1_i = ((java.math.BigInteger)(java.lang.Object)(_1_i_boxed0));
      return (((Hole)(java.lang.Object)((_0_hs).select(dafny.Helpers.toInt((_1_i)))))).dtor_hid();
    });}).apply(hs));
  }
  public static boolean EscsTyped(Ontology ont, Goal g)
  {
    return ((dafny.Function2<Goal, Ontology, Boolean>)(_0_g, _1_ont) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_0_g).dtor_escalateOn()).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf(((_0_g).dtor_escalateOn()).length())) < 0)) || (__default.CondTyped(((Cond)(java.lang.Object)(((_0_g).dtor_escalateOn()).select(dafny.Helpers.toInt((_2_i))))), ((java.util.function.Function<Ontology, dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean>>)(_3_ont) -> {return ((dafny.Function2<dafny.DafnySequence<? extends dafny.CodePoint>, Ty, Boolean>)(_4_p_boxed0, _5_ty_boxed0) -> {
        dafny.DafnySequence<? extends dafny.CodePoint> _4_p = ((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(_4_p_boxed0));
        Ty _5_ty = ((Ty)(java.lang.Object)(_5_ty_boxed0));
        return __default.NoConflict((_3_ont).dtor_verbs(), _4_p, _5_ty);
      });}).apply(_1_ont)));
    }));}).apply(g, ont);
  }
  public static boolean Sorted4(Goal g) {
    return (((__default.StrictlySorted(__default.Gids((g).dtor_grants()))) && (__default.StrictlySorted(__default.Pids((g).dtor_prohibits())))) && (__default.StrictlySorted(__default.Bids((g).dtor_bounds())))) && (__default.StrictlySorted(__default.Hids((g).dtor_holes())));
  }
  public static boolean IsWellTyped(Ontology ont, Goal g)
  {
    return ((((((__default.Sorted4(g)) && (((dafny.Function2<Goal, Ontology, Boolean>)(_0_g, _1_ont) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_0_g).dtor_grants()).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf(((_0_g).dtor_grants()).length())) < 0)) || (__default.GrantOk(_1_ont, _0_g, ((Grant)(java.lang.Object)(((_0_g).dtor_grants()).select(dafny.Helpers.toInt((_2_i)))))));
    }));}).apply(g, ont))) && (((dafny.Function2<Goal, Ontology, Boolean>)(_3_g, _4_ont) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_3_g).dtor_prohibits()).length())), true, ((_forall_var_1_boxed0) -> {
      java.math.BigInteger _forall_var_1 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_1_boxed0));
      java.math.BigInteger _5_i = (java.math.BigInteger)_forall_var_1;
      return !(((_5_i).signum() != -1) && ((_5_i).compareTo(java.math.BigInteger.valueOf(((_3_g).dtor_prohibits()).length())) < 0)) || (__default.ProhibitOk(_4_ont, ((Prohibit)(java.lang.Object)(((_3_g).dtor_prohibits()).select(dafny.Helpers.toInt((_5_i)))))));
    }));}).apply(g, ont))) && (((dafny.Function2<Goal, Ontology, Boolean>)(_6_g, _7_ont) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_6_g).dtor_bounds()).length())), true, ((_forall_var_2_boxed0) -> {
      java.math.BigInteger _forall_var_2 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_2_boxed0));
      java.math.BigInteger _8_i = (java.math.BigInteger)_forall_var_2;
      return !(((_8_i).signum() != -1) && ((_8_i).compareTo(java.math.BigInteger.valueOf(((_6_g).dtor_bounds()).length())) < 0)) || (__default.BoundOk(_7_ont, _6_g, ((Bound)(java.lang.Object)(((_6_g).dtor_bounds()).select(dafny.Helpers.toInt((_8_i)))))));
    }));}).apply(g, ont))) && (__default.EscsTyped(ont, g))) && (__default.ValidityOk((g).dtor_validity(), (g).dtor_deleg(), g))) && (((java.util.function.Function<Goal, Boolean>)(_9_g) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_9_g).dtor_holes()).length())), true, ((_forall_var_3_boxed0) -> {
      java.math.BigInteger _forall_var_3 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_3_boxed0));
      java.math.BigInteger _10_i = (java.math.BigInteger)_forall_var_3;
      return !(((_10_i).signum() != -1) && ((_10_i).compareTo(java.math.BigInteger.valueOf(((_9_g).dtor_holes()).length())) < 0)) || (__default.HoleOk(_9_g, ((Hole)(java.lang.Object)(((_9_g).dtor_holes()).select(dafny.Helpers.toInt((_10_i)))))));
    }));}).apply(g));
  }
  public static boolean Signable(Ontology ont, Goal g)
  {
    return (__default.IsWellTyped(ont, g)) && ((java.math.BigInteger.valueOf(((g).dtor_holes()).length())).signum() == 0);
  }
  public static java.math.BigInteger Deny()
  {
    return java.math.BigInteger.ZERO;
  }
  public static java.math.BigInteger Escalate()
  {
    return java.math.BigInteger.ONE;
  }
  public static java.math.BigInteger Allow()
  {
    return java.math.BigInteger.valueOf(2L);
  }
  public static java.math.BigInteger KF()
  {
    return java.math.BigInteger.ZERO;
  }
  public static java.math.BigInteger KU()
  {
    return java.math.BigInteger.ONE;
  }
  public static java.math.BigInteger KT()
  {
    return java.math.BigInteger.valueOf(2L);
  }
  @Override
  public java.lang.String toString() {
    return "GoalIr._default";
  }
}
