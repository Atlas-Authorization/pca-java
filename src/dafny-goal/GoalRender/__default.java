// Class __default
// Dafny class __default compiled into Java
package GoalRender;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static dafny.DafnySequence<? extends Tok> EncStr(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TS(s));
  }
  public static PR<dafny.DafnySequence<? extends dafny.CodePoint>> DecStr(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TS())) {
      return PR.<dafny.DafnySequence<? extends dafny.CodePoint>>create_Ok(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_s(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<dafny.DafnySequence<? extends dafny.CodePoint>>create_Fail(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncInt(java.math.BigInteger i) {
    return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(i));
  }
  public static PR<java.math.BigInteger> DecInt(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) {
      return PR.<java.math.BigInteger>create_Ok(dafny.TypeDescriptor.BIG_INTEGER, (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<java.math.BigInteger>create_Fail(dafny.TypeDescriptor.BIG_INTEGER);
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncBool(boolean b) {
    return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(((b) ? (java.math.BigInteger.ONE) : (java.math.BigInteger.ZERO))));
  }
  public static PR<Boolean> DecBool(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && ((((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() == 0) || (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i(), java.math.BigInteger.ONE)))) {
      return PR.<Boolean>create_Ok(dafny.TypeDescriptor.BOOLEAN, java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i(), java.math.BigInteger.ONE), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<Boolean>create_Fail(dafny.TypeDescriptor.BOOLEAN);
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncUnit(GoalIr.Unit u) {
    GoalIr.Unit _source0 = u;
    if (_source0.is_UMoney()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.Unit_UMoney)_source0)._ccy;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_c = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(300L))), __default.EncStr(_1_c));
    } else if (_source0.is_UCount()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(301L)));
    } else if (_source0.is_UDuration()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(302L)));
    } else if (_source0.is_UInstant()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(303L)));
    } else if (_source0.is_UBytes()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(304L)));
    } else {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(305L)));
    }
  }
  public static PR<GoalIr.Unit> DecUnit(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Unit>create_Fail(GoalIr.Unit._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(300L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Unit>create_Fail(GoalIr.Unit._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_c = _0___mcc_h0;
        return PR.<GoalIr.Unit>create_Ok(GoalIr.Unit._typeDescriptor(), GoalIr.Unit.create_UMoney(_3_c), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(301L))) {
      return PR.<GoalIr.Unit>create_Ok(GoalIr.Unit._typeDescriptor(), GoalIr.Unit.create_UCount(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(302L))) {
      return PR.<GoalIr.Unit>create_Ok(GoalIr.Unit._typeDescriptor(), GoalIr.Unit.create_UDuration(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(303L))) {
      return PR.<GoalIr.Unit>create_Ok(GoalIr.Unit._typeDescriptor(), GoalIr.Unit.create_UInstant(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(304L))) {
      return PR.<GoalIr.Unit>create_Ok(GoalIr.Unit._typeDescriptor(), GoalIr.Unit.create_UBytes(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(305L))) {
      return PR.<GoalIr.Unit>create_Ok(GoalIr.Unit._typeDescriptor(), GoalIr.Unit.create_URatio(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<GoalIr.Unit>create_Fail(GoalIr.Unit._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncQ(GoalIr.Q q) {
    return dafny.DafnySequence.<Tok>concatenate(__default.EncUnit((q).dtor_u()), __default.EncInt((q).dtor_n()));
  }
  public static PR<GoalIr.Q> DecQ(dafny.DafnySequence<? extends Tok> ts) {
    PR<GoalIr.Unit> _source0 = __default.DecUnit(ts);
    if (_source0.is_Fail()) {
      return PR.<GoalIr.Q>create_Fail(GoalIr.Q._typeDescriptor());
    } else {
      GoalIr.Unit _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Unit>)_source0)._v;
      dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Unit>)_source0)._rest;
      dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
      GoalIr.Unit _3_u = _0___mcc_h0;
      PR<java.math.BigInteger> _source1 = __default.DecInt(_2_r);
      if (_source1.is_Fail()) {
        return PR.<GoalIr.Q>create_Fail(GoalIr.Q._typeDescriptor());
      } else {
        java.math.BigInteger _4___mcc_h2 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
        java.math.BigInteger _7_n = _4___mcc_h2;
        return PR.<GoalIr.Q>create_Ok(GoalIr.Q._typeDescriptor(), GoalIr.Q.create(_3_u, _7_n), _6_r2);
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncTy(GoalIr.Ty t) {
    GoalIr.Ty _source0 = t;
    if (_source0.is_TyQ()) {
      GoalIr.Unit _0___mcc_h0 = ((GoalIr.Ty_TyQ)_source0)._u;
      GoalIr.Unit _1_u = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(310L))), __default.EncUnit(_1_u));
    } else {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(311L)));
    }
  }
  public static PR<GoalIr.Ty> DecTy(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Ty>create_Fail(GoalIr.Ty._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(310L))) {
      PR<GoalIr.Unit> _source0 = __default.DecUnit((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Ty>create_Fail(GoalIr.Ty._typeDescriptor());
      } else {
        GoalIr.Unit _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Unit>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Unit>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Unit _3_u = _0___mcc_h0;
        return PR.<GoalIr.Ty>create_Ok(GoalIr.Ty._typeDescriptor(), GoalIr.Ty.create_TyQ(_3_u), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(311L))) {
      return PR.<GoalIr.Ty>create_Ok(GoalIr.Ty._typeDescriptor(), GoalIr.Ty.create_TyS(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<GoalIr.Ty>create_Fail(GoalIr.Ty._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncAtom(GoalIr.Atom a) {
    GoalIr.Atom _source0 = a;
    if (_source0.is_AQ()) {
      GoalIr.Q _0___mcc_h0 = ((GoalIr.Atom_AQ)_source0)._q;
      GoalIr.Q _1_q = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(320L))), __default.EncQ(_1_q));
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.Atom_AS)_source0)._s;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_s = _2___mcc_h1;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(321L))), __default.EncStr(_3_s));
    }
  }
  public static PR<GoalIr.Atom> DecAtom(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Atom>create_Fail(GoalIr.Atom._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(320L))) {
      PR<GoalIr.Q> _source0 = __default.DecQ((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Atom>create_Fail(GoalIr.Atom._typeDescriptor());
      } else {
        GoalIr.Q _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Q>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Q>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Q _3_q = _0___mcc_h0;
        return PR.<GoalIr.Atom>create_Ok(GoalIr.Atom._typeDescriptor(), GoalIr.Atom.create_AQ(_3_q), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(321L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source1.is_Fail()) {
        return PR.<GoalIr.Atom>create_Fail(GoalIr.Atom._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r = _5___mcc_h3;
        dafny.DafnySequence<? extends dafny.CodePoint> _7_s = _4___mcc_h2;
        return PR.<GoalIr.Atom>create_Ok(GoalIr.Atom._typeDescriptor(), GoalIr.Atom.create_AS(_7_s), _6_r);
      }
    } else {
      return PR.<GoalIr.Atom>create_Fail(GoalIr.Atom._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncAtomsElems(dafny.DafnySequence<? extends GoalIr.Atom> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncAtom(((GoalIr.Atom)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalIr.Atom> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncAtoms(dafny.DafnySequence<? extends GoalIr.Atom> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncAtomsElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Atom>> DecAtomsElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends GoalIr.Atom>>create_Ok(dafny.DafnySequence.<GoalIr.Atom>_typeDescriptor(GoalIr.Atom._typeDescriptor()), dafny.DafnySequence.<GoalIr.Atom> empty(GoalIr.Atom._typeDescriptor()), ts);
    } else {
      PR<GoalIr.Atom> _source0 = __default.DecAtom(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends GoalIr.Atom>>create_Fail(dafny.DafnySequence.<GoalIr.Atom>_typeDescriptor(GoalIr.Atom._typeDescriptor()));
      } else {
        GoalIr.Atom _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Atom>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Atom>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Atom _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.Atom>> _source1 = __default.DecAtomsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends GoalIr.Atom>>create_Fail(dafny.DafnySequence.<GoalIr.Atom>_typeDescriptor(GoalIr.Atom._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.Atom> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Atom>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Atom>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Atom> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends GoalIr.Atom>>create_Ok(dafny.DafnySequence.<GoalIr.Atom>_typeDescriptor(GoalIr.Atom._typeDescriptor()), dafny.DafnySequence.<GoalIr.Atom>concatenate(dafny.DafnySequence.<GoalIr.Atom> of(GoalIr.Atom._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Atom>> DecAtoms(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecAtomsElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends GoalIr.Atom>>create_Fail(dafny.DafnySequence.<GoalIr.Atom>_typeDescriptor(GoalIr.Atom._typeDescriptor()));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncV(GoalIr.V v) {
    GoalIr.V _source0 = v;
    if (_source0.is_VQ()) {
      GoalIr.Q _0___mcc_h0 = ((GoalIr.V_VQ)_source0)._q;
      GoalIr.Q _1_q = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(330L))), __default.EncQ(_1_q));
    } else if (_source0.is_VS()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.V_VS)_source0)._s;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_s = _2___mcc_h1;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(331L))), __default.EncStr(_3_s));
    } else {
      dafny.DafnySequence<? extends GoalIr.Atom> _4___mcc_h2 = ((GoalIr.V_VSet)_source0)._items;
      dafny.DafnySequence<? extends GoalIr.Atom> _5_items = _4___mcc_h2;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(332L))), __default.EncAtoms(_5_items));
    }
  }
  public static PR<GoalIr.V> DecV(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.V>create_Fail(GoalIr.V._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(330L))) {
      PR<GoalIr.Q> _source0 = __default.DecQ((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.V>create_Fail(GoalIr.V._typeDescriptor());
      } else {
        GoalIr.Q _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Q>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Q>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Q _3_q = _0___mcc_h0;
        return PR.<GoalIr.V>create_Ok(GoalIr.V._typeDescriptor(), GoalIr.V.create_VQ(_3_q), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(331L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source1.is_Fail()) {
        return PR.<GoalIr.V>create_Fail(GoalIr.V._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r = _5___mcc_h3;
        dafny.DafnySequence<? extends dafny.CodePoint> _7_s = _4___mcc_h2;
        return PR.<GoalIr.V>create_Ok(GoalIr.V._typeDescriptor(), GoalIr.V.create_VS(_7_s), _6_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(332L))) {
      PR<dafny.DafnySequence<? extends GoalIr.Atom>> _source2 = __default.DecAtoms((ts).drop(java.math.BigInteger.ONE));
      if (_source2.is_Fail()) {
        return PR.<GoalIr.V>create_Fail(GoalIr.V._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends GoalIr.Atom> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Atom>>)_source2)._v;
        dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Atom>>)_source2)._rest;
        dafny.DafnySequence<? extends Tok> _10_r = _9___mcc_h5;
        dafny.DafnySequence<? extends GoalIr.Atom> _11_xs = _8___mcc_h4;
        return PR.<GoalIr.V>create_Ok(GoalIr.V._typeDescriptor(), GoalIr.V.create_VSet(_11_xs), _10_r);
      }
    } else {
      return PR.<GoalIr.V>create_Fail(GoalIr.V._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncTerm(GoalIr.Term t) {
    GoalIr.Term _source0 = t;
    if (_source0.is_Param()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.Term_Param)_source0)._path;
      GoalIr.Ty _1___mcc_h1 = ((GoalIr.Term_Param)_source0)._ty;
      GoalIr.Ty _2_ty = _1___mcc_h1;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_p = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(340L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr(_3_p), __default.EncTy(_2_ty)));
    } else if (_source0.is_Lit()) {
      GoalIr.V _4___mcc_h2 = ((GoalIr.Term_Lit)_source0)._v;
      GoalIr.V _5_v = _4___mcc_h2;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(341L))), __default.EncV(_5_v));
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _6___mcc_h3 = ((GoalIr.Term_HistAgg)_source0)._bid;
      GoalIr.Unit _7___mcc_h4 = ((GoalIr.Term_HistAgg)_source0)._u;
      GoalIr.Unit _8_u = _7___mcc_h4;
      dafny.DafnySequence<? extends dafny.CodePoint> _9_b = _6___mcc_h3;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(342L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr(_9_b), __default.EncUnit(_8_u)));
    }
  }
  public static PR<GoalIr.Term> DecTerm(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Term>create_Fail(GoalIr.Term._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(340L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Term>create_Fail(GoalIr.Term._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_p = _0___mcc_h0;
        PR<GoalIr.Ty> _source1 = __default.DecTy(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Term>create_Fail(GoalIr.Term._typeDescriptor());
        } else {
          GoalIr.Ty _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.Ty>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.Ty>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          GoalIr.Ty _7_ty = _4___mcc_h2;
          return PR.<GoalIr.Term>create_Ok(GoalIr.Term._typeDescriptor(), GoalIr.Term.create_Param(_3_p, _7_ty), _6_r2);
        }
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(341L))) {
      PR<GoalIr.V> _source2 = __default.DecV((ts).drop(java.math.BigInteger.ONE));
      if (_source2.is_Fail()) {
        return PR.<GoalIr.Term>create_Fail(GoalIr.Term._typeDescriptor());
      } else {
        GoalIr.V _8___mcc_h4 = ((GoalRender.PR_Ok<GoalIr.V>)_source2)._v;
        dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<GoalIr.V>)_source2)._rest;
        dafny.DafnySequence<? extends Tok> _10_r = _9___mcc_h5;
        GoalIr.V _11_v = _8___mcc_h4;
        return PR.<GoalIr.Term>create_Ok(GoalIr.Term._typeDescriptor(), GoalIr.Term.create_Lit(_11_v), _10_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(342L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source3 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source3.is_Fail()) {
        return PR.<GoalIr.Term>create_Fail(GoalIr.Term._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _12___mcc_h6 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source3)._v;
        dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source3)._rest;
        dafny.DafnySequence<? extends Tok> _14_r1 = _13___mcc_h7;
        dafny.DafnySequence<? extends dafny.CodePoint> _15_b = _12___mcc_h6;
        PR<GoalIr.Unit> _source4 = __default.DecUnit(_14_r1);
        if (_source4.is_Fail()) {
          return PR.<GoalIr.Term>create_Fail(GoalIr.Term._typeDescriptor());
        } else {
          GoalIr.Unit _16___mcc_h8 = ((GoalRender.PR_Ok<GoalIr.Unit>)_source4)._v;
          dafny.DafnySequence<? extends Tok> _17___mcc_h9 = ((GoalRender.PR_Ok<GoalIr.Unit>)_source4)._rest;
          dafny.DafnySequence<? extends Tok> _18_r2 = _17___mcc_h9;
          GoalIr.Unit _19_u = _16___mcc_h8;
          return PR.<GoalIr.Term>create_Ok(GoalIr.Term._typeDescriptor(), GoalIr.Term.create_HistAgg(_15_b, _19_u), _18_r2);
        }
      }
    } else {
      return PR.<GoalIr.Term>create_Fail(GoalIr.Term._typeDescriptor());
    }
  }
  public static java.math.BigInteger OpIdx(GoalIr.Op op) {
    GoalIr.Op _source0 = op;
    if (_source0.is_Eq()) {
      return java.math.BigInteger.ZERO;
    } else if (_source0.is_Ne()) {
      return java.math.BigInteger.ONE;
    } else if (_source0.is_Lt()) {
      return java.math.BigInteger.valueOf(2L);
    } else if (_source0.is_Lte()) {
      return java.math.BigInteger.valueOf(3L);
    } else if (_source0.is_Gt()) {
      return java.math.BigInteger.valueOf(4L);
    } else if (_source0.is_Gte()) {
      return java.math.BigInteger.valueOf(5L);
    } else if (_source0.is_In()) {
      return java.math.BigInteger.valueOf(6L);
    } else {
      return java.math.BigInteger.valueOf(7L);
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncOp(GoalIr.Op op) {
    return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw((java.math.BigInteger.valueOf(350L)).add(__default.OpIdx(op))));
  }
  public static PR<GoalIr.Op> DecOp(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Op>create_Fail(GoalIr.Op._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(350L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_Eq(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(351L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_Ne(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(352L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_Lt(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(353L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_Lte(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(354L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_Gt(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(355L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_Gte(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(356L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_In(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(357L))) {
      return PR.<GoalIr.Op>create_Ok(GoalIr.Op._typeDescriptor(), GoalIr.Op.create_Nin(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<GoalIr.Op>create_Fail(GoalIr.Op._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncCond(GoalIr.Cond c) {
    GoalIr.Cond _source0 = c;
    if (_source0.is_CTrue()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(360L)));
    } else if (_source0.is_Cmp()) {
      GoalIr.Op _0___mcc_h0 = ((GoalIr.Cond_Cmp)_source0)._op;
      GoalIr.Term _1___mcc_h1 = ((GoalIr.Cond_Cmp)_source0)._l;
      GoalIr.Term _2___mcc_h2 = ((GoalIr.Cond_Cmp)_source0)._r;
      GoalIr.Term _3_r = _2___mcc_h2;
      GoalIr.Term _4_l = _1___mcc_h1;
      GoalIr.Op _5_op = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(361L))), dafny.DafnySequence.<Tok>concatenate(__default.EncOp(_5_op), dafny.DafnySequence.<Tok>concatenate(__default.EncTerm(_4_l), __default.EncTerm(_3_r))));
    } else if (_source0.is_And()) {
      GoalIr.Cond _6___mcc_h3 = ((GoalIr.Cond_And)_source0)._a;
      GoalIr.Cond _7___mcc_h4 = ((GoalIr.Cond_And)_source0)._b;
      GoalIr.Cond _8_y = _7___mcc_h4;
      GoalIr.Cond _9_x = _6___mcc_h3;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(362L))), dafny.DafnySequence.<Tok>concatenate(__default.EncCond(_9_x), __default.EncCond(_8_y)));
    } else if (_source0.is_Or()) {
      GoalIr.Cond _10___mcc_h5 = ((GoalIr.Cond_Or)_source0)._a;
      GoalIr.Cond _11___mcc_h6 = ((GoalIr.Cond_Or)_source0)._b;
      GoalIr.Cond _12_y = _11___mcc_h6;
      GoalIr.Cond _13_x = _10___mcc_h5;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(363L))), dafny.DafnySequence.<Tok>concatenate(__default.EncCond(_13_x), __default.EncCond(_12_y)));
    } else {
      GoalIr.Cond _14___mcc_h7 = ((GoalIr.Cond_Not)_source0)._c;
      GoalIr.Cond _15_x = _14___mcc_h7;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(364L))), __default.EncCond(_15_x));
    }
  }
  public static PR<GoalIr.Cond> DecCond(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger fuel)
  {
    if ((((fuel).signum() == 0) || ((java.math.BigInteger.valueOf((ts).length())).signum() == 0)) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(360L))) {
      return PR.<GoalIr.Cond>create_Ok(GoalIr.Cond._typeDescriptor(), GoalIr.Cond.create_CTrue(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(361L))) {
      PR<GoalIr.Op> _source0 = __default.DecOp((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
      } else {
        GoalIr.Op _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Op>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Op>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        GoalIr.Op _3_op = _0___mcc_h0;
        PR<GoalIr.Term> _source1 = __default.DecTerm(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
        } else {
          GoalIr.Term _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.Term>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.Term>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          GoalIr.Term _7_l = _4___mcc_h2;
          PR<GoalIr.Term> _source2 = __default.DecTerm(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
          } else {
            GoalIr.Term _8___mcc_h4 = ((GoalRender.PR_Ok<GoalIr.Term>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<GoalIr.Term>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            GoalIr.Term _11_r = _8___mcc_h4;
            return PR.<GoalIr.Cond>create_Ok(GoalIr.Cond._typeDescriptor(), GoalIr.Cond.create_Cmp(_3_op, _7_l, _11_r), _10_r3);
          }
        }
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(362L))) {
      PR<GoalIr.Cond> _source3 = __default.DecCond((ts).drop(java.math.BigInteger.ONE), (fuel).subtract(java.math.BigInteger.ONE));
      if (_source3.is_Fail()) {
        return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
      } else {
        GoalIr.Cond _12___mcc_h6 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source3)._v;
        dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source3)._rest;
        dafny.DafnySequence<? extends Tok> _14_r1 = _13___mcc_h7;
        GoalIr.Cond _15_x = _12___mcc_h6;
        PR<GoalIr.Cond> _source4 = __default.DecCond(_14_r1, (fuel).subtract(java.math.BigInteger.ONE));
        if (_source4.is_Fail()) {
          return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
        } else {
          GoalIr.Cond _16___mcc_h8 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source4)._v;
          dafny.DafnySequence<? extends Tok> _17___mcc_h9 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source4)._rest;
          dafny.DafnySequence<? extends Tok> _18_r2 = _17___mcc_h9;
          GoalIr.Cond _19_y = _16___mcc_h8;
          return PR.<GoalIr.Cond>create_Ok(GoalIr.Cond._typeDescriptor(), GoalIr.Cond.create_And(_15_x, _19_y), _18_r2);
        }
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(363L))) {
      PR<GoalIr.Cond> _source5 = __default.DecCond((ts).drop(java.math.BigInteger.ONE), (fuel).subtract(java.math.BigInteger.ONE));
      if (_source5.is_Fail()) {
        return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
      } else {
        GoalIr.Cond _20___mcc_h10 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source5)._v;
        dafny.DafnySequence<? extends Tok> _21___mcc_h11 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source5)._rest;
        dafny.DafnySequence<? extends Tok> _22_r1 = _21___mcc_h11;
        GoalIr.Cond _23_x = _20___mcc_h10;
        PR<GoalIr.Cond> _source6 = __default.DecCond(_22_r1, (fuel).subtract(java.math.BigInteger.ONE));
        if (_source6.is_Fail()) {
          return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
        } else {
          GoalIr.Cond _24___mcc_h12 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source6)._v;
          dafny.DafnySequence<? extends Tok> _25___mcc_h13 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source6)._rest;
          dafny.DafnySequence<? extends Tok> _26_r2 = _25___mcc_h13;
          GoalIr.Cond _27_y = _24___mcc_h12;
          return PR.<GoalIr.Cond>create_Ok(GoalIr.Cond._typeDescriptor(), GoalIr.Cond.create_Or(_23_x, _27_y), _26_r2);
        }
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(364L))) {
      PR<GoalIr.Cond> _source7 = __default.DecCond((ts).drop(java.math.BigInteger.ONE), (fuel).subtract(java.math.BigInteger.ONE));
      if (_source7.is_Fail()) {
        return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
      } else {
        GoalIr.Cond _28___mcc_h14 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source7)._v;
        dafny.DafnySequence<? extends Tok> _29___mcc_h15 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source7)._rest;
        dafny.DafnySequence<? extends Tok> _30_r = _29___mcc_h15;
        GoalIr.Cond _31_x = _28___mcc_h14;
        return PR.<GoalIr.Cond>create_Ok(GoalIr.Cond._typeDescriptor(), GoalIr.Cond.create_Not(_31_x), _30_r);
      }
    } else {
      return PR.<GoalIr.Cond>create_Fail(GoalIr.Cond._typeDescriptor());
    }
  }
  public static PR<GoalIr.Cond> DecCondTop(dafny.DafnySequence<? extends Tok> ts) {
    return __default.DecCond(ts, java.math.BigInteger.valueOf((ts).length()));
  }
  public static java.math.BigInteger Depth(GoalIr.Cond c) {
    GoalIr.Cond _source0 = c;
    if (_source0.is_CTrue()) {
      return java.math.BigInteger.ONE;
    } else if (_source0.is_Cmp()) {
      GoalIr.Op _0___mcc_h0 = ((GoalIr.Cond_Cmp)_source0)._op;
      GoalIr.Term _1___mcc_h1 = ((GoalIr.Cond_Cmp)_source0)._l;
      GoalIr.Term _2___mcc_h2 = ((GoalIr.Cond_Cmp)_source0)._r;
      return java.math.BigInteger.ONE;
    } else if (_source0.is_And()) {
      GoalIr.Cond _3___mcc_h3 = ((GoalIr.Cond_And)_source0)._a;
      GoalIr.Cond _4___mcc_h4 = ((GoalIr.Cond_And)_source0)._b;
      GoalIr.Cond _5_y = _4___mcc_h4;
      GoalIr.Cond _6_x = _3___mcc_h3;
      return (java.math.BigInteger.ONE).add((((__default.Depth(_6_x)).compareTo(__default.Depth(_5_y)) >= 0) ? (__default.Depth(_6_x)) : (__default.Depth(_5_y))));
    } else if (_source0.is_Or()) {
      GoalIr.Cond _7___mcc_h5 = ((GoalIr.Cond_Or)_source0)._a;
      GoalIr.Cond _8___mcc_h6 = ((GoalIr.Cond_Or)_source0)._b;
      GoalIr.Cond _9_y = _8___mcc_h6;
      GoalIr.Cond _10_x = _7___mcc_h5;
      return (java.math.BigInteger.ONE).add((((__default.Depth(_10_x)).compareTo(__default.Depth(_9_y)) >= 0) ? (__default.Depth(_10_x)) : (__default.Depth(_9_y))));
    } else {
      GoalIr.Cond _11___mcc_h7 = ((GoalIr.Cond_Not)_source0)._c;
      GoalIr.Cond _12_x = _11___mcc_h7;
      return (java.math.BigInteger.ONE).add(__default.Depth(_12_x));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncPart(GoalIr.ResPart p) {
    GoalIr.ResPart _source0 = p;
    if (_source0.is_PartExact()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ResPart_PartExact)_source0)._id;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_id = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(375L))), __default.EncStr(_1_id));
    } else if (_source0.is_PartOneOf()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _2___mcc_h1 = ((GoalIr.ResPart_PartOneOf)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_ids = _2___mcc_h1;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(376L))), __default.EncStrs(_3_ids));
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalIr.ResPart_PartRelated)_source0)._rel;
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.ResPart_PartRelated)_source0)._anchor;
      dafny.DafnySequence<? extends dafny.CodePoint> _6_anchor = _5___mcc_h3;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_rel = _4___mcc_h2;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(377L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr(_7_rel), __default.EncStr(_6_anchor)));
    }
  }
  public static PR<GoalIr.ResPart> DecPart(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.ResPart>create_Fail(GoalIr.ResPart._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(375L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.ResPart>create_Fail(GoalIr.ResPart._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_id = _0___mcc_h0;
        return PR.<GoalIr.ResPart>create_Ok(GoalIr.ResPart._typeDescriptor(), GoalIr.ResPart.create_PartExact(_3_id), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(376L))) {
      PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source1 = __default.DecStrs((ts).drop(java.math.BigInteger.ONE));
      if (_source1.is_Fail()) {
        return PR.<GoalIr.ResPart>create_Fail(GoalIr.ResPart._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r = _5___mcc_h3;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _7_ids = _4___mcc_h2;
        return PR.<GoalIr.ResPart>create_Ok(GoalIr.ResPart._typeDescriptor(), GoalIr.ResPart.create_PartOneOf(_7_ids), _6_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(377L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source2 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source2.is_Fail()) {
        return PR.<GoalIr.ResPart>create_Fail(GoalIr.ResPart._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source2)._v;
        dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source2)._rest;
        dafny.DafnySequence<? extends Tok> _10_r1 = _9___mcc_h5;
        dafny.DafnySequence<? extends dafny.CodePoint> _11_rel = _8___mcc_h4;
        PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source3 = __default.DecStr(_10_r1);
        if (_source3.is_Fail()) {
          return PR.<GoalIr.ResPart>create_Fail(GoalIr.ResPart._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends dafny.CodePoint> _12___mcc_h6 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source3)._v;
          dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source3)._rest;
          dafny.DafnySequence<? extends Tok> _14_r2 = _13___mcc_h7;
          dafny.DafnySequence<? extends dafny.CodePoint> _15_anchor = _12___mcc_h6;
          return PR.<GoalIr.ResPart>create_Ok(GoalIr.ResPart._typeDescriptor(), GoalIr.ResPart.create_PartRelated(_11_rel, _15_anchor), _14_r2);
        }
      }
    } else {
      return PR.<GoalIr.ResPart>create_Fail(GoalIr.ResPart._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncPartsElems(dafny.DafnySequence<? extends GoalIr.ResPart> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncPart(((GoalIr.ResPart)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalIr.ResPart> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncParts(dafny.DafnySequence<? extends GoalIr.ResPart> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncPartsElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.ResPart>> DecPartsElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends GoalIr.ResPart>>create_Ok(dafny.DafnySequence.<GoalIr.ResPart>_typeDescriptor(GoalIr.ResPart._typeDescriptor()), dafny.DafnySequence.<GoalIr.ResPart> empty(GoalIr.ResPart._typeDescriptor()), ts);
    } else {
      PR<GoalIr.ResPart> _source0 = __default.DecPart(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends GoalIr.ResPart>>create_Fail(dafny.DafnySequence.<GoalIr.ResPart>_typeDescriptor(GoalIr.ResPart._typeDescriptor()));
      } else {
        GoalIr.ResPart _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.ResPart>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.ResPart>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.ResPart _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.ResPart>> _source1 = __default.DecPartsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends GoalIr.ResPart>>create_Fail(dafny.DafnySequence.<GoalIr.ResPart>_typeDescriptor(GoalIr.ResPart._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.ResPart> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ResPart>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ResPart>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.ResPart> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends GoalIr.ResPart>>create_Ok(dafny.DafnySequence.<GoalIr.ResPart>_typeDescriptor(GoalIr.ResPart._typeDescriptor()), dafny.DafnySequence.<GoalIr.ResPart>concatenate(dafny.DafnySequence.<GoalIr.ResPart> of(GoalIr.ResPart._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.ResPart>> DecParts(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecPartsElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends GoalIr.ResPart>>create_Fail(dafny.DafnySequence.<GoalIr.ResPart>_typeDescriptor(GoalIr.ResPart._typeDescriptor()));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncResSel(GoalIr.ResSel s) {
    GoalIr.ResSel _source0 = s;
    if (_source0.is_Exact()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ResSel_Exact)_source0)._id;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_id = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(370L))), __default.EncStr(_1_id));
    } else if (_source0.is_OneOf()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _2___mcc_h1 = ((GoalIr.ResSel_OneOf)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_ids = _2___mcc_h1;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(371L))), __default.EncStrs(_3_ids));
    } else if (_source0.is_Related()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalIr.ResSel_Related)_source0)._rel;
      dafny.DafnySequence<? extends dafny.CodePoint> _5___mcc_h3 = ((GoalIr.ResSel_Related)_source0)._anchor;
      dafny.DafnySequence<? extends dafny.CodePoint> _6_anchor = _5___mcc_h3;
      dafny.DafnySequence<? extends dafny.CodePoint> _7_rel = _4___mcc_h2;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(372L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr(_7_rel), __default.EncStr(_6_anchor)));
    } else if (_source0.is_AnyRes()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _8___mcc_h4 = ((GoalIr.ResSel_AnyRes)_source0)._reason;
      dafny.DafnySequence<? extends dafny.CodePoint> _9_reason = _8___mcc_h4;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(373L))), __default.EncStr(_9_reason));
    } else {
      dafny.DafnySequence<? extends GoalIr.ResPart> _10___mcc_h5 = ((GoalIr.ResSel_AllOf)_source0)._parts;
      dafny.DafnySequence<? extends GoalIr.ResPart> _11_ps = _10___mcc_h5;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(374L))), __default.EncParts(_11_ps));
    }
  }
  public static PR<GoalIr.ResSel> DecResSel(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(370L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_id = _0___mcc_h0;
        return PR.<GoalIr.ResSel>create_Ok(GoalIr.ResSel._typeDescriptor(), GoalIr.ResSel.create_Exact(_3_id), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(371L))) {
      PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source1 = __default.DecStrs((ts).drop(java.math.BigInteger.ONE));
      if (_source1.is_Fail()) {
        return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r = _5___mcc_h3;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _7_ids = _4___mcc_h2;
        return PR.<GoalIr.ResSel>create_Ok(GoalIr.ResSel._typeDescriptor(), GoalIr.ResSel.create_OneOf(_7_ids), _6_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(372L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source2 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source2.is_Fail()) {
        return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source2)._v;
        dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source2)._rest;
        dafny.DafnySequence<? extends Tok> _10_r1 = _9___mcc_h5;
        dafny.DafnySequence<? extends dafny.CodePoint> _11_rel = _8___mcc_h4;
        PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source3 = __default.DecStr(_10_r1);
        if (_source3.is_Fail()) {
          return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends dafny.CodePoint> _12___mcc_h6 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source3)._v;
          dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source3)._rest;
          dafny.DafnySequence<? extends Tok> _14_r2 = _13___mcc_h7;
          dafny.DafnySequence<? extends dafny.CodePoint> _15_anchor = _12___mcc_h6;
          return PR.<GoalIr.ResSel>create_Ok(GoalIr.ResSel._typeDescriptor(), GoalIr.ResSel.create_Related(_11_rel, _15_anchor), _14_r2);
        }
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(373L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source4 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source4.is_Fail()) {
        return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _16___mcc_h8 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source4)._v;
        dafny.DafnySequence<? extends Tok> _17___mcc_h9 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source4)._rest;
        dafny.DafnySequence<? extends Tok> _18_r = _17___mcc_h9;
        dafny.DafnySequence<? extends dafny.CodePoint> _19_reason = _16___mcc_h8;
        return PR.<GoalIr.ResSel>create_Ok(GoalIr.ResSel._typeDescriptor(), GoalIr.ResSel.create_AnyRes(_19_reason), _18_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(374L))) {
      PR<dafny.DafnySequence<? extends GoalIr.ResPart>> _source5 = __default.DecParts((ts).drop(java.math.BigInteger.ONE));
      if (_source5.is_Fail()) {
        return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends GoalIr.ResPart> _20___mcc_h10 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ResPart>>)_source5)._v;
        dafny.DafnySequence<? extends Tok> _21___mcc_h11 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ResPart>>)_source5)._rest;
        dafny.DafnySequence<? extends Tok> _22_r = _21___mcc_h11;
        dafny.DafnySequence<? extends GoalIr.ResPart> _23_ps = _20___mcc_h10;
        return PR.<GoalIr.ResSel>create_Ok(GoalIr.ResSel._typeDescriptor(), GoalIr.ResSel.create_AllOf(_23_ps), _22_r);
      }
    } else {
      return PR.<GoalIr.ResSel>create_Fail(GoalIr.ResSel._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncGrant(GoalIr.Grant g) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(380L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr((g).dtor_gid()), dafny.DafnySequence.<Tok>concatenate(__default.EncStr((g).dtor_verb()), dafny.DafnySequence.<Tok>concatenate(__default.EncResSel((g).dtor_res()), __default.EncCond((g).dtor_cond())))));
  }
  public static PR<GoalIr.Grant> DecGrant(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(380L))))) {
      return PR.<GoalIr.Grant>create_Fail(GoalIr.Grant._typeDescriptor());
    } else {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Grant>create_Fail(GoalIr.Grant._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_gid = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = __default.DecStr(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Grant>create_Fail(GoalIr.Grant._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends dafny.CodePoint> _7_verb = _4___mcc_h2;
          PR<GoalIr.ResSel> _source2 = __default.DecResSel(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Grant>create_Fail(GoalIr.Grant._typeDescriptor());
          } else {
            GoalIr.ResSel _8___mcc_h4 = ((GoalRender.PR_Ok<GoalIr.ResSel>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<GoalIr.ResSel>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            GoalIr.ResSel _11_res = _8___mcc_h4;
            PR<GoalIr.Cond> _source3 = __default.DecCondTop(_10_r3);
            if (_source3.is_Fail()) {
              return PR.<GoalIr.Grant>create_Fail(GoalIr.Grant._typeDescriptor());
            } else {
              GoalIr.Cond _12___mcc_h6 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source3)._v;
              dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source3)._rest;
              dafny.DafnySequence<? extends Tok> _14_r4 = _13___mcc_h7;
              GoalIr.Cond _15_c = _12___mcc_h6;
              return PR.<GoalIr.Grant>create_Ok(GoalIr.Grant._typeDescriptor(), GoalIr.Grant.create(_3_gid, _7_verb, _11_res, _15_c), _14_r4);
            }
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncProhTarget(GoalIr.ProhTarget t) {
    GoalIr.ProhTarget _source0 = t;
    if (_source0.is_PVerb()) {
      dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalIr.ProhTarget_PVerb)_source0)._verb;
      dafny.DafnySequence<? extends dafny.CodePoint> _1_v = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(390L))), __default.EncStr(_1_v));
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.ProhTarget_PEffect)_source0)._cls;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_c = _2___mcc_h1;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(391L))), __default.EncStr(_3_c));
    }
  }
  public static PR<GoalIr.ProhTarget> DecProhTarget(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.ProhTarget>create_Fail(GoalIr.ProhTarget._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(390L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.ProhTarget>create_Fail(GoalIr.ProhTarget._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_v = _0___mcc_h0;
        return PR.<GoalIr.ProhTarget>create_Ok(GoalIr.ProhTarget._typeDescriptor(), GoalIr.ProhTarget.create_PVerb(_3_v), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(391L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source1.is_Fail()) {
        return PR.<GoalIr.ProhTarget>create_Fail(GoalIr.ProhTarget._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r = _5___mcc_h3;
        dafny.DafnySequence<? extends dafny.CodePoint> _7_c = _4___mcc_h2;
        return PR.<GoalIr.ProhTarget>create_Ok(GoalIr.ProhTarget._typeDescriptor(), GoalIr.ProhTarget.create_PEffect(_7_c), _6_r);
      }
    } else {
      return PR.<GoalIr.ProhTarget>create_Fail(GoalIr.ProhTarget._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncProhibit(GoalIr.Prohibit p) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(392L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr((p).dtor_pid()), dafny.DafnySequence.<Tok>concatenate(__default.EncProhTarget((p).dtor_target()), dafny.DafnySequence.<Tok>concatenate(__default.EncResSel((p).dtor_res()), __default.EncCond((p).dtor_cond())))));
  }
  public static PR<GoalIr.Prohibit> DecProhibit(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(392L))))) {
      return PR.<GoalIr.Prohibit>create_Fail(GoalIr.Prohibit._typeDescriptor());
    } else {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Prohibit>create_Fail(GoalIr.Prohibit._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_pid = _0___mcc_h0;
        PR<GoalIr.ProhTarget> _source1 = __default.DecProhTarget(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Prohibit>create_Fail(GoalIr.Prohibit._typeDescriptor());
        } else {
          GoalIr.ProhTarget _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.ProhTarget>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.ProhTarget>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          GoalIr.ProhTarget _7_tg = _4___mcc_h2;
          PR<GoalIr.ResSel> _source2 = __default.DecResSel(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Prohibit>create_Fail(GoalIr.Prohibit._typeDescriptor());
          } else {
            GoalIr.ResSel _8___mcc_h4 = ((GoalRender.PR_Ok<GoalIr.ResSel>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<GoalIr.ResSel>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            GoalIr.ResSel _11_res = _8___mcc_h4;
            PR<GoalIr.Cond> _source3 = __default.DecCondTop(_10_r3);
            if (_source3.is_Fail()) {
              return PR.<GoalIr.Prohibit>create_Fail(GoalIr.Prohibit._typeDescriptor());
            } else {
              GoalIr.Cond _12___mcc_h6 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source3)._v;
              dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source3)._rest;
              dafny.DafnySequence<? extends Tok> _14_r4 = _13___mcc_h7;
              GoalIr.Cond _15_c = _12___mcc_h6;
              return PR.<GoalIr.Prohibit>create_Ok(GoalIr.Prohibit._typeDescriptor(), GoalIr.Prohibit.create(_3_pid, _7_tg, _11_res, _15_c), _14_r4);
            }
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncAgg(GoalIr.Agg a) {
    GoalIr.Agg _source0 = a;
    if (_source0.is_ACount()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(400L)));
    } else if (_source0.is_ASum()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(401L)));
    } else if (_source0.is_AMax()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(402L)));
    } else {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(403L)));
    }
  }
  public static PR<GoalIr.Agg> DecAgg(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Agg>create_Fail(GoalIr.Agg._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(400L))) {
      return PR.<GoalIr.Agg>create_Ok(GoalIr.Agg._typeDescriptor(), GoalIr.Agg.create_ACount(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(401L))) {
      return PR.<GoalIr.Agg>create_Ok(GoalIr.Agg._typeDescriptor(), GoalIr.Agg.create_ASum(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(402L))) {
      return PR.<GoalIr.Agg>create_Ok(GoalIr.Agg._typeDescriptor(), GoalIr.Agg.create_AMax(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(403L))) {
      return PR.<GoalIr.Agg>create_Ok(GoalIr.Agg._typeDescriptor(), GoalIr.Agg.create_ADistinct(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<GoalIr.Agg>create_Fail(GoalIr.Agg._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncSel(GoalIr.Sel s) {
    GoalIr.Sel _source0 = s;
    if (_source0.is_SelGids()) {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.Sel_SelGids)_source0)._gids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_g = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(410L))), __default.EncStrs(_1_g));
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h1 = ((GoalIr.Sel_SelEffect)_source0)._cls;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_c = _2___mcc_h1;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(411L))), __default.EncStr(_3_c));
    }
  }
  public static PR<GoalIr.Sel> DecSel(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Sel>create_Fail(GoalIr.Sel._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(410L))) {
      PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source0 = __default.DecStrs((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Sel>create_Fail(GoalIr.Sel._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_g = _0___mcc_h0;
        return PR.<GoalIr.Sel>create_Ok(GoalIr.Sel._typeDescriptor(), GoalIr.Sel.create_SelGids(_3_g), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(411L))) {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source1.is_Fail()) {
        return PR.<GoalIr.Sel>create_Fail(GoalIr.Sel._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r = _5___mcc_h3;
        dafny.DafnySequence<? extends dafny.CodePoint> _7_c = _4___mcc_h2;
        return PR.<GoalIr.Sel>create_Ok(GoalIr.Sel._typeDescriptor(), GoalIr.Sel.create_SelEffect(_7_c), _6_r);
      }
    } else {
      return PR.<GoalIr.Sel>create_Fail(GoalIr.Sel._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncWindow(GoalIr.Window w) {
    GoalIr.Window _source0 = w;
    if (_source0.is_WTask()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(420L)));
    } else if (_source0.is_WSliding()) {
      java.math.BigInteger _0___mcc_h0 = ((GoalIr.Window_WSliding)_source0)._ms;
      java.math.BigInteger _1_ms = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(421L))), __default.EncInt(_1_ms));
    } else if (_source0.is_WPeriod()) {
      java.math.BigInteger _2___mcc_h1 = ((GoalIr.Window_WPeriod)_source0)._ms;
      java.math.BigInteger _3___mcc_h2 = ((GoalIr.Window_WPeriod)_source0)._t0;
      java.math.BigInteger _4_t0 = _3___mcc_h2;
      java.math.BigInteger _5_ms = _2___mcc_h1;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(422L))), dafny.DafnySequence.<Tok>concatenate(__default.EncInt(_5_ms), __default.EncInt(_4_t0)));
    } else {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(423L)));
    }
  }
  public static PR<GoalIr.Window> DecWindow(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Window>create_Fail(GoalIr.Window._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(420L))) {
      return PR.<GoalIr.Window>create_Ok(GoalIr.Window._typeDescriptor(), GoalIr.Window.create_WTask(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(421L))) {
      PR<java.math.BigInteger> _source0 = __default.DecInt((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Window>create_Fail(GoalIr.Window._typeDescriptor());
      } else {
        java.math.BigInteger _0___mcc_h0 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        java.math.BigInteger _3_ms = _0___mcc_h0;
        return PR.<GoalIr.Window>create_Ok(GoalIr.Window._typeDescriptor(), GoalIr.Window.create_WSliding(_3_ms), _2_r);
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(422L))) {
      PR<java.math.BigInteger> _source1 = __default.DecInt((ts).drop(java.math.BigInteger.ONE));
      if (_source1.is_Fail()) {
        return PR.<GoalIr.Window>create_Fail(GoalIr.Window._typeDescriptor());
      } else {
        java.math.BigInteger _4___mcc_h2 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._v;
        dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._rest;
        dafny.DafnySequence<? extends Tok> _6_r1 = _5___mcc_h3;
        java.math.BigInteger _7_ms = _4___mcc_h2;
        PR<java.math.BigInteger> _source2 = __default.DecInt(_6_r1);
        if (_source2.is_Fail()) {
          return PR.<GoalIr.Window>create_Fail(GoalIr.Window._typeDescriptor());
        } else {
          java.math.BigInteger _8___mcc_h4 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source2)._v;
          dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source2)._rest;
          dafny.DafnySequence<? extends Tok> _10_r2 = _9___mcc_h5;
          java.math.BigInteger _11_t0 = _8___mcc_h4;
          return PR.<GoalIr.Window>create_Ok(GoalIr.Window._typeDescriptor(), GoalIr.Window.create_WPeriod(_7_ms, _11_t0), _10_r2);
        }
      }
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(423L))) {
      return PR.<GoalIr.Window>create_Ok(GoalIr.Window._typeDescriptor(), GoalIr.Window.create_WLifetime(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<GoalIr.Window>create_Fail(GoalIr.Window._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncScope(GoalIr.Scope s) {
    GoalIr.Scope _source0 = s;
    if (_source0.is_SSession()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(430L)));
    } else if (_source0.is_SPrincipal()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(431L)));
    } else if (_source0.is_SOrg()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(432L)));
    } else {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.Scope_SFleet)_source0)._agents;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_a = _0___mcc_h0;
      return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(433L))), __default.EncStrs(_1_a));
    }
  }
  public static PR<GoalIr.Scope> DecScope(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.Scope>create_Fail(GoalIr.Scope._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(430L))) {
      return PR.<GoalIr.Scope>create_Ok(GoalIr.Scope._typeDescriptor(), GoalIr.Scope.create_SSession(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(431L))) {
      return PR.<GoalIr.Scope>create_Ok(GoalIr.Scope._typeDescriptor(), GoalIr.Scope.create_SPrincipal(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(432L))) {
      return PR.<GoalIr.Scope>create_Ok(GoalIr.Scope._typeDescriptor(), GoalIr.Scope.create_SOrg(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(433L))) {
      PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source0 = __default.DecStrs((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Scope>create_Fail(GoalIr.Scope._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_a = _0___mcc_h0;
        return PR.<GoalIr.Scope>create_Ok(GoalIr.Scope._typeDescriptor(), GoalIr.Scope.create_SFleet(_3_a), _2_r);
      }
    } else {
      return PR.<GoalIr.Scope>create_Fail(GoalIr.Scope._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncOnExceed(GoalIr.OnExceed o) {
    GoalIr.OnExceed _source0 = o;
    if (_source0.is_OnDeny()) {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(440L)));
    } else {
      return dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(441L)));
    }
  }
  public static PR<GoalIr.OnExceed> DecOnExceed(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TKw()))) {
      return PR.<GoalIr.OnExceed>create_Fail(GoalIr.OnExceed._typeDescriptor());
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(440L))) {
      return PR.<GoalIr.OnExceed>create_Ok(GoalIr.OnExceed._typeDescriptor(), GoalIr.OnExceed.create_OnDeny(), (ts).drop(java.math.BigInteger.ONE));
    } else if (java.util.Objects.equals((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_k(), java.math.BigInteger.valueOf(441L))) {
      return PR.<GoalIr.OnExceed>create_Ok(GoalIr.OnExceed._typeDescriptor(), GoalIr.OnExceed.create_OnEscalate(), (ts).drop(java.math.BigInteger.ONE));
    } else {
      return PR.<GoalIr.OnExceed>create_Fail(GoalIr.OnExceed._typeDescriptor());
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncBCore(GoalIr.BCore b) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(450L))), dafny.DafnySequence.<Tok>concatenate(__default.EncAgg((b).dtor_agg()), dafny.DafnySequence.<Tok>concatenate(__default.EncTerm((b).dtor_value()), dafny.DafnySequence.<Tok>concatenate(__default.EncStr((b).dtor_key()), dafny.DafnySequence.<Tok>concatenate(__default.EncWindow((b).dtor_window()), dafny.DafnySequence.<Tok>concatenate(__default.EncScope((b).dtor_scope()), dafny.DafnySequence.<Tok>concatenate(__default.EncQ((b).dtor_cap()), __default.EncOnExceed((b).dtor_onExceed()))))))));
  }
  public static PR<GoalIr.BCore> DecBCore(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(450L))))) {
      return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
    } else {
      PR<GoalIr.Agg> _source0 = __default.DecAgg((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
      } else {
        GoalIr.Agg _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Agg>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Agg>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        GoalIr.Agg _3_agg = _0___mcc_h0;
        PR<GoalIr.Term> _source1 = __default.DecTerm(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
        } else {
          GoalIr.Term _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.Term>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.Term>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          GoalIr.Term _7_value = _4___mcc_h2;
          PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source2 = __default.DecStr(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
          } else {
            dafny.DafnySequence<? extends dafny.CodePoint> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnySequence<? extends dafny.CodePoint> _11_key = _8___mcc_h4;
            PR<GoalIr.Window> _source3 = __default.DecWindow(_10_r3);
            if (_source3.is_Fail()) {
              return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
            } else {
              GoalIr.Window _12___mcc_h6 = ((GoalRender.PR_Ok<GoalIr.Window>)_source3)._v;
              dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<GoalIr.Window>)_source3)._rest;
              dafny.DafnySequence<? extends Tok> _14_r4 = _13___mcc_h7;
              GoalIr.Window _15_window = _12___mcc_h6;
              PR<GoalIr.Scope> _source4 = __default.DecScope(_14_r4);
              if (_source4.is_Fail()) {
                return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
              } else {
                GoalIr.Scope _16___mcc_h8 = ((GoalRender.PR_Ok<GoalIr.Scope>)_source4)._v;
                dafny.DafnySequence<? extends Tok> _17___mcc_h9 = ((GoalRender.PR_Ok<GoalIr.Scope>)_source4)._rest;
                dafny.DafnySequence<? extends Tok> _18_r5 = _17___mcc_h9;
                GoalIr.Scope _19_scope = _16___mcc_h8;
                PR<GoalIr.Q> _source5 = __default.DecQ(_18_r5);
                if (_source5.is_Fail()) {
                  return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
                } else {
                  GoalIr.Q _20___mcc_h10 = ((GoalRender.PR_Ok<GoalIr.Q>)_source5)._v;
                  dafny.DafnySequence<? extends Tok> _21___mcc_h11 = ((GoalRender.PR_Ok<GoalIr.Q>)_source5)._rest;
                  dafny.DafnySequence<? extends Tok> _22_r6 = _21___mcc_h11;
                  GoalIr.Q _23_cap = _20___mcc_h10;
                  PR<GoalIr.OnExceed> _source6 = __default.DecOnExceed(_22_r6);
                  if (_source6.is_Fail()) {
                    return PR.<GoalIr.BCore>create_Fail(GoalIr.BCore._typeDescriptor());
                  } else {
                    GoalIr.OnExceed _24___mcc_h12 = ((GoalRender.PR_Ok<GoalIr.OnExceed>)_source6)._v;
                    dafny.DafnySequence<? extends Tok> _25___mcc_h13 = ((GoalRender.PR_Ok<GoalIr.OnExceed>)_source6)._rest;
                    dafny.DafnySequence<? extends Tok> _26_r7 = _25___mcc_h13;
                    GoalIr.OnExceed _27_oe = _24___mcc_h12;
                    return PR.<GoalIr.BCore>create_Ok(GoalIr.BCore._typeDescriptor(), GoalIr.BCore.create(_3_agg, _7_value, _11_key, _15_window, _19_scope, _23_cap, _27_oe), _26_r7);
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncBound(GoalIr.Bound b) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(451L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr((b).dtor_bid()), dafny.DafnySequence.<Tok>concatenate(__default.EncSel((b).dtor_sel()), __default.EncBCore((b).dtor_core()))));
  }
  public static PR<GoalIr.Bound> DecBound(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(451L))))) {
      return PR.<GoalIr.Bound>create_Fail(GoalIr.Bound._typeDescriptor());
    } else {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Bound>create_Fail(GoalIr.Bound._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_bid = _0___mcc_h0;
        PR<GoalIr.Sel> _source1 = __default.DecSel(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Bound>create_Fail(GoalIr.Bound._typeDescriptor());
        } else {
          GoalIr.Sel _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.Sel>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.Sel>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          GoalIr.Sel _7_sel = _4___mcc_h2;
          PR<GoalIr.BCore> _source2 = __default.DecBCore(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Bound>create_Fail(GoalIr.Bound._typeDescriptor());
          } else {
            GoalIr.BCore _8___mcc_h4 = ((GoalRender.PR_Ok<GoalIr.BCore>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<GoalIr.BCore>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            GoalIr.BCore _11_core = _8___mcc_h4;
            return PR.<GoalIr.Bound>create_Ok(GoalIr.Bound._typeDescriptor(), GoalIr.Bound.create(_3_bid, _7_sel, _11_core), _10_r3);
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncValidity(GoalIr.Validity v) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(460L))), dafny.DafnySequence.<Tok>concatenate(__default.EncInt((v).dtor_notBefore()), dafny.DafnySequence.<Tok>concatenate(__default.EncInt((v).dtor_notAfter()), __default.EncInt((v).dtor_maxIdle()))));
  }
  public static PR<GoalIr.Validity> DecValidity(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(460L))))) {
      return PR.<GoalIr.Validity>create_Fail(GoalIr.Validity._typeDescriptor());
    } else {
      PR<java.math.BigInteger> _source0 = __default.DecInt((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Validity>create_Fail(GoalIr.Validity._typeDescriptor());
      } else {
        java.math.BigInteger _0___mcc_h0 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        java.math.BigInteger _3_nb = _0___mcc_h0;
        PR<java.math.BigInteger> _source1 = __default.DecInt(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Validity>create_Fail(GoalIr.Validity._typeDescriptor());
        } else {
          java.math.BigInteger _4___mcc_h2 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          java.math.BigInteger _7_na = _4___mcc_h2;
          PR<java.math.BigInteger> _source2 = __default.DecInt(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Validity>create_Fail(GoalIr.Validity._typeDescriptor());
          } else {
            java.math.BigInteger _8___mcc_h4 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            java.math.BigInteger _11_mi = _8___mcc_h4;
            return PR.<GoalIr.Validity>create_Ok(GoalIr.Validity._typeDescriptor(), GoalIr.Validity.create(_3_nb, _7_na, _11_mi), _10_r3);
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncDeleg(GoalIr.Delegation d) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(461L))), dafny.DafnySequence.<Tok>concatenate(__default.EncInt((d).dtor_maxDepth()), dafny.DafnySequence.<Tok>concatenate(__default.EncBool((d).dtor_narrowOnly()), __default.EncStrs((d).dtor_mayTouch()))));
  }
  public static PR<GoalIr.Delegation> DecDeleg(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(461L))))) {
      return PR.<GoalIr.Delegation>create_Fail(GoalIr.Delegation._typeDescriptor());
    } else {
      PR<java.math.BigInteger> _source0 = __default.DecInt((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Delegation>create_Fail(GoalIr.Delegation._typeDescriptor());
      } else {
        java.math.BigInteger _0___mcc_h0 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        java.math.BigInteger _3_md = _0___mcc_h0;
        PR<Boolean> _source1 = __default.DecBool(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Delegation>create_Fail(GoalIr.Delegation._typeDescriptor());
        } else {
          boolean _4___mcc_h2 = ((GoalRender.PR_Ok<Boolean>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<Boolean>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          boolean _7_no = _4___mcc_h2;
          PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source2 = __default.DecStrs(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Delegation>create_Fail(GoalIr.Delegation._typeDescriptor());
          } else {
            dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _11_mt = _8___mcc_h4;
            return PR.<GoalIr.Delegation>create_Ok(GoalIr.Delegation._typeDescriptor(), GoalIr.Delegation.create(_3_md, _7_no, _11_mt), _10_r3);
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncHole(GoalIr.Hole h) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(470L))), dafny.DafnySequence.<Tok>concatenate(__default.EncStr((h).dtor_hid()), dafny.DafnySequence.<Tok>concatenate(__default.EncStr((h).dtor_q()), dafny.DafnySequence.<Tok>concatenate(__default.EncStrs((h).dtor_domain()), dafny.DafnySequence.<Tok>concatenate(__default.EncStrs((h).dtor_affects()), __default.EncBool((h).dtor_global()))))));
  }
  public static PR<GoalIr.Hole> DecHole(dafny.DafnySequence<? extends Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(470L))))) {
      return PR.<GoalIr.Hole>create_Fail(GoalIr.Hole._typeDescriptor());
    } else {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Hole>create_Fail(GoalIr.Hole._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_hid = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = __default.DecStr(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Hole>create_Fail(GoalIr.Hole._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends dafny.CodePoint> _7_q = _4___mcc_h2;
          PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source2 = __default.DecStrs(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Hole>create_Fail(GoalIr.Hole._typeDescriptor());
          } else {
            dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _11_dom = _8___mcc_h4;
            PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source3 = __default.DecStrs(_10_r3);
            if (_source3.is_Fail()) {
              return PR.<GoalIr.Hole>create_Fail(GoalIr.Hole._typeDescriptor());
            } else {
              dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _12___mcc_h6 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source3)._v;
              dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source3)._rest;
              dafny.DafnySequence<? extends Tok> _14_r4 = _13___mcc_h7;
              dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _15_aff = _12___mcc_h6;
              PR<Boolean> _source4 = __default.DecBool(_14_r4);
              if (_source4.is_Fail()) {
                return PR.<GoalIr.Hole>create_Fail(GoalIr.Hole._typeDescriptor());
              } else {
                boolean _16___mcc_h8 = ((GoalRender.PR_Ok<Boolean>)_source4)._v;
                dafny.DafnySequence<? extends Tok> _17___mcc_h9 = ((GoalRender.PR_Ok<Boolean>)_source4)._rest;
                dafny.DafnySequence<? extends Tok> _18_r5 = _17___mcc_h9;
                boolean _19_gl = _16___mcc_h8;
                return PR.<GoalIr.Hole>create_Ok(GoalIr.Hole._typeDescriptor(), GoalIr.Hole.create(_3_hid, _7_q, _11_dom, _15_aff, _19_gl), _18_r5);
              }
            }
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncStrsElems(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncStr(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncStrs(dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncStrsElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> DecStrsElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>create_Ok(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), ts);
    } else {
      PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = __default.DecStr(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>create_Fail(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source1 = __default.DecStrsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>create_Fail(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
        } else {
          dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>create_Ok(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> DecStrs(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecStrsElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>create_Fail(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncGrantsElems(dafny.DafnySequence<? extends GoalIr.Grant> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncGrant(((GoalIr.Grant)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalIr.Grant> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncGrants(dafny.DafnySequence<? extends GoalIr.Grant> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncGrantsElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Grant>> DecGrantsElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends GoalIr.Grant>>create_Ok(dafny.DafnySequence.<GoalIr.Grant>_typeDescriptor(GoalIr.Grant._typeDescriptor()), dafny.DafnySequence.<GoalIr.Grant> empty(GoalIr.Grant._typeDescriptor()), ts);
    } else {
      PR<GoalIr.Grant> _source0 = __default.DecGrant(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends GoalIr.Grant>>create_Fail(dafny.DafnySequence.<GoalIr.Grant>_typeDescriptor(GoalIr.Grant._typeDescriptor()));
      } else {
        GoalIr.Grant _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Grant>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Grant>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Grant _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.Grant>> _source1 = __default.DecGrantsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends GoalIr.Grant>>create_Fail(dafny.DafnySequence.<GoalIr.Grant>_typeDescriptor(GoalIr.Grant._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.Grant> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Grant>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Grant>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Grant> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends GoalIr.Grant>>create_Ok(dafny.DafnySequence.<GoalIr.Grant>_typeDescriptor(GoalIr.Grant._typeDescriptor()), dafny.DafnySequence.<GoalIr.Grant>concatenate(dafny.DafnySequence.<GoalIr.Grant> of(GoalIr.Grant._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Grant>> DecGrants(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecGrantsElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends GoalIr.Grant>>create_Fail(dafny.DafnySequence.<GoalIr.Grant>_typeDescriptor(GoalIr.Grant._typeDescriptor()));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncProhibitsElems(dafny.DafnySequence<? extends GoalIr.Prohibit> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncProhibit(((GoalIr.Prohibit)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalIr.Prohibit> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncProhibits(dafny.DafnySequence<? extends GoalIr.Prohibit> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncProhibitsElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Prohibit>> DecProhibitsElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends GoalIr.Prohibit>>create_Ok(dafny.DafnySequence.<GoalIr.Prohibit>_typeDescriptor(GoalIr.Prohibit._typeDescriptor()), dafny.DafnySequence.<GoalIr.Prohibit> empty(GoalIr.Prohibit._typeDescriptor()), ts);
    } else {
      PR<GoalIr.Prohibit> _source0 = __default.DecProhibit(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends GoalIr.Prohibit>>create_Fail(dafny.DafnySequence.<GoalIr.Prohibit>_typeDescriptor(GoalIr.Prohibit._typeDescriptor()));
      } else {
        GoalIr.Prohibit _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Prohibit>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Prohibit>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Prohibit _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.Prohibit>> _source1 = __default.DecProhibitsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends GoalIr.Prohibit>>create_Fail(dafny.DafnySequence.<GoalIr.Prohibit>_typeDescriptor(GoalIr.Prohibit._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.Prohibit> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Prohibit>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Prohibit>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Prohibit> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends GoalIr.Prohibit>>create_Ok(dafny.DafnySequence.<GoalIr.Prohibit>_typeDescriptor(GoalIr.Prohibit._typeDescriptor()), dafny.DafnySequence.<GoalIr.Prohibit>concatenate(dafny.DafnySequence.<GoalIr.Prohibit> of(GoalIr.Prohibit._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Prohibit>> DecProhibits(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecProhibitsElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends GoalIr.Prohibit>>create_Fail(dafny.DafnySequence.<GoalIr.Prohibit>_typeDescriptor(GoalIr.Prohibit._typeDescriptor()));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncBoundsElems(dafny.DafnySequence<? extends GoalIr.Bound> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncBound(((GoalIr.Bound)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalIr.Bound> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncBounds(dafny.DafnySequence<? extends GoalIr.Bound> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncBoundsElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Bound>> DecBoundsElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends GoalIr.Bound>>create_Ok(dafny.DafnySequence.<GoalIr.Bound>_typeDescriptor(GoalIr.Bound._typeDescriptor()), dafny.DafnySequence.<GoalIr.Bound> empty(GoalIr.Bound._typeDescriptor()), ts);
    } else {
      PR<GoalIr.Bound> _source0 = __default.DecBound(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends GoalIr.Bound>>create_Fail(dafny.DafnySequence.<GoalIr.Bound>_typeDescriptor(GoalIr.Bound._typeDescriptor()));
      } else {
        GoalIr.Bound _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Bound>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Bound>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Bound _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.Bound>> _source1 = __default.DecBoundsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends GoalIr.Bound>>create_Fail(dafny.DafnySequence.<GoalIr.Bound>_typeDescriptor(GoalIr.Bound._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.Bound> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Bound>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Bound>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Bound> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends GoalIr.Bound>>create_Ok(dafny.DafnySequence.<GoalIr.Bound>_typeDescriptor(GoalIr.Bound._typeDescriptor()), dafny.DafnySequence.<GoalIr.Bound>concatenate(dafny.DafnySequence.<GoalIr.Bound> of(GoalIr.Bound._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Bound>> DecBounds(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecBoundsElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends GoalIr.Bound>>create_Fail(dafny.DafnySequence.<GoalIr.Bound>_typeDescriptor(GoalIr.Bound._typeDescriptor()));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncCondsElems(dafny.DafnySequence<? extends GoalIr.Cond> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncCond(((GoalIr.Cond)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalIr.Cond> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncConds(dafny.DafnySequence<? extends GoalIr.Cond> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncCondsElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Cond>> DecCondsElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends GoalIr.Cond>>create_Ok(dafny.DafnySequence.<GoalIr.Cond>_typeDescriptor(GoalIr.Cond._typeDescriptor()), dafny.DafnySequence.<GoalIr.Cond> empty(GoalIr.Cond._typeDescriptor()), ts);
    } else {
      PR<GoalIr.Cond> _source0 = __default.DecCondTop(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends GoalIr.Cond>>create_Fail(dafny.DafnySequence.<GoalIr.Cond>_typeDescriptor(GoalIr.Cond._typeDescriptor()));
      } else {
        GoalIr.Cond _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Cond>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Cond _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.Cond>> _source1 = __default.DecCondsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends GoalIr.Cond>>create_Fail(dafny.DafnySequence.<GoalIr.Cond>_typeDescriptor(GoalIr.Cond._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.Cond> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Cond>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Cond>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Cond> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends GoalIr.Cond>>create_Ok(dafny.DafnySequence.<GoalIr.Cond>_typeDescriptor(GoalIr.Cond._typeDescriptor()), dafny.DafnySequence.<GoalIr.Cond>concatenate(dafny.DafnySequence.<GoalIr.Cond> of(GoalIr.Cond._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Cond>> DecConds(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecCondsElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends GoalIr.Cond>>create_Fail(dafny.DafnySequence.<GoalIr.Cond>_typeDescriptor(GoalIr.Cond._typeDescriptor()));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncHolesElems(dafny.DafnySequence<? extends GoalIr.Hole> xs) {
    dafny.DafnySequence<? extends Tok> _0___accumulator = dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<Tok>concatenate(_0___accumulator, dafny.DafnySequence.<Tok> empty(Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<Tok>concatenate(_0___accumulator, __default.EncHole(((GoalIr.Hole)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalIr.Hole> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncHoles(dafny.DafnySequence<? extends GoalIr.Hole> xs) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncHolesElems(xs));
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Hole>> DecHolesElems(dafny.DafnySequence<? extends Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return PR.<dafny.DafnySequence<? extends GoalIr.Hole>>create_Ok(dafny.DafnySequence.<GoalIr.Hole>_typeDescriptor(GoalIr.Hole._typeDescriptor()), dafny.DafnySequence.<GoalIr.Hole> empty(GoalIr.Hole._typeDescriptor()), ts);
    } else {
      PR<GoalIr.Hole> _source0 = __default.DecHole(ts);
      if (_source0.is_Fail()) {
        return PR.<dafny.DafnySequence<? extends GoalIr.Hole>>create_Fail(dafny.DafnySequence.<GoalIr.Hole>_typeDescriptor(GoalIr.Hole._typeDescriptor()));
      } else {
        GoalIr.Hole _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Hole>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Hole>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r = _1___mcc_h1;
        GoalIr.Hole _3_x = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.Hole>> _source1 = __default.DecHolesElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return PR.<dafny.DafnySequence<? extends GoalIr.Hole>>create_Fail(dafny.DafnySequence.<GoalIr.Hole>_typeDescriptor(GoalIr.Hole._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.Hole> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Hole>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Hole>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Hole> _7_xs = _4___mcc_h2;
          return PR.<dafny.DafnySequence<? extends GoalIr.Hole>>create_Ok(dafny.DafnySequence.<GoalIr.Hole>_typeDescriptor(GoalIr.Hole._typeDescriptor()), dafny.DafnySequence.<GoalIr.Hole>concatenate(dafny.DafnySequence.<GoalIr.Hole> of(GoalIr.Hole._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static PR<dafny.DafnySequence<? extends GoalIr.Hole>> DecHoles(dafny.DafnySequence<? extends Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecHolesElems((ts).drop(java.math.BigInteger.ONE), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return PR.<dafny.DafnySequence<? extends GoalIr.Hole>>create_Fail(dafny.DafnySequence.<GoalIr.Hole>_typeDescriptor(GoalIr.Hole._typeDescriptor()));
    }
  }
  public static dafny.DafnySequence<? extends Tok> EncGoal(GoalIr.Goal g) {
    return dafny.DafnySequence.<Tok>concatenate(dafny.DafnySequence.<Tok> of(Tok._typeDescriptor(), Tok.create_TKw(java.math.BigInteger.valueOf(480L)), Tok.create_TI((g).dtor_v()), Tok.create_TS((g).dtor_principal()), Tok.create_TS((g).dtor_ontDigest()), Tok.create_TS((g).dtor_nlDigest())), dafny.DafnySequence.<Tok>concatenate(__default.EncStrs((g).dtor_sources()), dafny.DafnySequence.<Tok>concatenate(__default.EncGrants((g).dtor_grants()), dafny.DafnySequence.<Tok>concatenate(__default.EncProhibits((g).dtor_prohibits()), dafny.DafnySequence.<Tok>concatenate(__default.EncBounds((g).dtor_bounds()), dafny.DafnySequence.<Tok>concatenate(__default.EncValidity((g).dtor_validity()), dafny.DafnySequence.<Tok>concatenate(__default.EncDeleg((g).dtor_deleg()), dafny.DafnySequence.<Tok>concatenate(__default.EncConds((g).dtor_escalateOn()), dafny.DafnySequence.<Tok>concatenate(__default.EncStrs((g).dtor_wildcardAck()), __default.EncHoles((g).dtor_holes()))))))))));
  }
  public static PR<GoalIr.Goal> DecGoal(dafny.DafnySequence<? extends Tok> ts) {
    if (((((((java.math.BigInteger.valueOf((ts).length())).compareTo(java.math.BigInteger.valueOf(5L)) < 0) || (!java.util.Objects.equals(((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), Tok.create_TKw(java.math.BigInteger.valueOf(480L))))) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ONE)))))).is_TI()))) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(2L))))))).is_TS()))) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(3L))))))).is_TS()))) || (!((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(4L))))))).is_TS()))) {
      return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
    } else {
      PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source0 = __default.DecStrs((ts).drop(java.math.BigInteger.valueOf(5L)));
      if (_source0.is_Fail()) {
        return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source0)._v;
        dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source0)._rest;
        dafny.DafnySequence<? extends Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _3_sources = _0___mcc_h0;
        PR<dafny.DafnySequence<? extends GoalIr.Grant>> _source1 = __default.DecGrants(_2_r1);
        if (_source1.is_Fail()) {
          return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends GoalIr.Grant> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Grant>>)_source1)._v;
          dafny.DafnySequence<? extends Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Grant>>)_source1)._rest;
          dafny.DafnySequence<? extends Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Grant> _7_grants = _4___mcc_h2;
          PR<dafny.DafnySequence<? extends GoalIr.Prohibit>> _source2 = __default.DecProhibits(_6_r2);
          if (_source2.is_Fail()) {
            return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
          } else {
            dafny.DafnySequence<? extends GoalIr.Prohibit> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Prohibit>>)_source2)._v;
            dafny.DafnySequence<? extends Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Prohibit>>)_source2)._rest;
            dafny.DafnySequence<? extends Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnySequence<? extends GoalIr.Prohibit> _11_prohibits = _8___mcc_h4;
            PR<dafny.DafnySequence<? extends GoalIr.Bound>> _source3 = __default.DecBounds(_10_r3);
            if (_source3.is_Fail()) {
              return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
            } else {
              dafny.DafnySequence<? extends GoalIr.Bound> _12___mcc_h6 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Bound>>)_source3)._v;
              dafny.DafnySequence<? extends Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Bound>>)_source3)._rest;
              dafny.DafnySequence<? extends Tok> _14_r4 = _13___mcc_h7;
              dafny.DafnySequence<? extends GoalIr.Bound> _15_bounds = _12___mcc_h6;
              PR<GoalIr.Validity> _source4 = __default.DecValidity(_14_r4);
              if (_source4.is_Fail()) {
                return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
              } else {
                GoalIr.Validity _16___mcc_h8 = ((GoalRender.PR_Ok<GoalIr.Validity>)_source4)._v;
                dafny.DafnySequence<? extends Tok> _17___mcc_h9 = ((GoalRender.PR_Ok<GoalIr.Validity>)_source4)._rest;
                dafny.DafnySequence<? extends Tok> _18_r5 = _17___mcc_h9;
                GoalIr.Validity _19_validity = _16___mcc_h8;
                PR<GoalIr.Delegation> _source5 = __default.DecDeleg(_18_r5);
                if (_source5.is_Fail()) {
                  return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
                } else {
                  GoalIr.Delegation _20___mcc_h10 = ((GoalRender.PR_Ok<GoalIr.Delegation>)_source5)._v;
                  dafny.DafnySequence<? extends Tok> _21___mcc_h11 = ((GoalRender.PR_Ok<GoalIr.Delegation>)_source5)._rest;
                  dafny.DafnySequence<? extends Tok> _22_r6 = _21___mcc_h11;
                  GoalIr.Delegation _23_deleg = _20___mcc_h10;
                  PR<dafny.DafnySequence<? extends GoalIr.Cond>> _source6 = __default.DecConds(_22_r6);
                  if (_source6.is_Fail()) {
                    return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
                  } else {
                    dafny.DafnySequence<? extends GoalIr.Cond> _24___mcc_h12 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Cond>>)_source6)._v;
                    dafny.DafnySequence<? extends Tok> _25___mcc_h13 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Cond>>)_source6)._rest;
                    dafny.DafnySequence<? extends Tok> _26_r7 = _25___mcc_h13;
                    dafny.DafnySequence<? extends GoalIr.Cond> _27_esc = _24___mcc_h12;
                    PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source7 = __default.DecStrs(_26_r7);
                    if (_source7.is_Fail()) {
                      return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
                    } else {
                      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _28___mcc_h14 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source7)._v;
                      dafny.DafnySequence<? extends Tok> _29___mcc_h15 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source7)._rest;
                      dafny.DafnySequence<? extends Tok> _30_r8 = _29___mcc_h15;
                      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _31_ack = _28___mcc_h14;
                      PR<dafny.DafnySequence<? extends GoalIr.Hole>> _source8 = __default.DecHoles(_30_r8);
                      if (_source8.is_Fail()) {
                        return PR.<GoalIr.Goal>create_Fail(GoalIr.Goal._typeDescriptor());
                      } else {
                        dafny.DafnySequence<? extends GoalIr.Hole> _32___mcc_h16 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Hole>>)_source8)._v;
                        dafny.DafnySequence<? extends Tok> _33___mcc_h17 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Hole>>)_source8)._rest;
                        dafny.DafnySequence<? extends Tok> _34_r9 = _33___mcc_h17;
                        dafny.DafnySequence<? extends GoalIr.Hole> _35_holes = _32___mcc_h16;
                        return PR.<GoalIr.Goal>create_Ok(GoalIr.Goal._typeDescriptor(), GoalIr.Goal.create((((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ONE)))))).dtor_i(), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(2L))))))).dtor_s(), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(3L))))))).dtor_s(), (((Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.valueOf(4L))))))).dtor_s(), _3_sources, _7_grants, _11_prohibits, _15_bounds, _19_validity, _23_deleg, _27_esc, _31_ack, _35_holes), _34_r9);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends Tok> Render(GoalIr.Goal g) {
    return __default.EncGoal(g);
  }
  public static GoalIr.Option<GoalIr.Goal> Parse(dafny.DafnySequence<? extends Tok> ts) {
    PR<GoalIr.Goal> _source0 = __default.DecGoal(ts);
    if (_source0.is_Fail()) {
      return GoalIr.Option.<GoalIr.Goal>create_None(GoalIr.Goal._typeDescriptor());
    } else {
      GoalIr.Goal _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Goal>)_source0)._v;
      dafny.DafnySequence<? extends Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Goal>)_source0)._rest;
      dafny.DafnySequence<? extends Tok> _2_rest = _1___mcc_h1;
      GoalIr.Goal _3_g = _0___mcc_h0;
      if ((java.math.BigInteger.valueOf((_2_rest).length())).signum() == 0) {
        return GoalIr.Option.<GoalIr.Goal>create_Some(GoalIr.Goal._typeDescriptor(), _3_g);
      } else {
        return GoalIr.Option.<GoalIr.Goal>create_None(GoalIr.Goal._typeDescriptor());
      }
    }
  }
  @Override
  public java.lang.String toString() {
    return "GoalRender._default";
  }
}
