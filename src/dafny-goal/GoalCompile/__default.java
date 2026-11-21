// Class __default
// Dafny class __default compiled into Java
package GoalCompile;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static java.math.BigInteger EvalN(NC c, GoalIr.Act a, GoalIr.Hist h)
  {
    NC _source0 = c;
    if (_source0.is_NTrue()) {
      return GoalIr.__default.KT();
    } else if (_source0.is_NFalse()) {
      return GoalIr.__default.KF();
    } else if (_source0.is_NAtom()) {
      GoalIr.Op _0___mcc_h0 = ((GoalCompile.NC_NAtom)_source0)._op;
      GoalIr.Term _1___mcc_h1 = ((GoalCompile.NC_NAtom)_source0)._l;
      GoalIr.Term _2___mcc_h2 = ((GoalCompile.NC_NAtom)_source0)._r;
      GoalIr.Term _3_r = _2___mcc_h2;
      GoalIr.Term _4_l = _1___mcc_h1;
      GoalIr.Op _5_op = _0___mcc_h0;
      return GoalIr.__default.CmpT(_5_op, GoalIr.__default.EvalT(_4_l, a, h), GoalIr.__default.EvalT(_3_r, a, h));
    } else if (_source0.is_NAnd()) {
      NC _6___mcc_h3 = ((GoalCompile.NC_NAnd)_source0)._a;
      NC _7___mcc_h4 = ((GoalCompile.NC_NAnd)_source0)._b;
      NC _8_y = _7___mcc_h4;
      NC _9_x = _6___mcc_h3;
      return GoalIr.__default.AndK(__default.EvalN(_9_x, a, h), __default.EvalN(_8_y, a, h));
    } else {
      NC _10___mcc_h5 = ((GoalCompile.NC_NOr)_source0)._a;
      NC _11___mcc_h6 = ((GoalCompile.NC_NOr)_source0)._b;
      NC _12_y = _11___mcc_h6;
      NC _13_x = _10___mcc_h5;
      return GoalIr.__default.OrK(__default.EvalN(_13_x, a, h), __default.EvalN(_12_y, a, h));
    }
  }
  public static NC Nnf(GoalIr.Cond c, boolean pos)
  {
    GoalIr.Cond _source0 = c;
    if (_source0.is_CTrue()) {
      if (pos) {
        return NC.create_NTrue();
      } else {
        return NC.create_NFalse();
      }
    } else if (_source0.is_Cmp()) {
      GoalIr.Op _0___mcc_h0 = ((GoalIr.Cond_Cmp)_source0)._op;
      GoalIr.Term _1___mcc_h1 = ((GoalIr.Cond_Cmp)_source0)._l;
      GoalIr.Term _2___mcc_h2 = ((GoalIr.Cond_Cmp)_source0)._r;
      GoalIr.Term _3_r = _2___mcc_h2;
      GoalIr.Term _4_l = _1___mcc_h1;
      GoalIr.Op _5_op = _0___mcc_h0;
      return NC.create_NAtom(((pos) ? (_5_op) : (GoalIr.__default.NegOp(_5_op))), _4_l, _3_r);
    } else if (_source0.is_And()) {
      GoalIr.Cond _6___mcc_h3 = ((GoalIr.Cond_And)_source0)._a;
      GoalIr.Cond _7___mcc_h4 = ((GoalIr.Cond_And)_source0)._b;
      GoalIr.Cond _8_y = _7___mcc_h4;
      GoalIr.Cond _9_x = _6___mcc_h3;
      if (pos) {
        return NC.create_NAnd(__default.Nnf(_9_x, true), __default.Nnf(_8_y, true));
      } else {
        return NC.create_NOr(__default.Nnf(_9_x, false), __default.Nnf(_8_y, false));
      }
    } else if (_source0.is_Or()) {
      GoalIr.Cond _10___mcc_h5 = ((GoalIr.Cond_Or)_source0)._a;
      GoalIr.Cond _11___mcc_h6 = ((GoalIr.Cond_Or)_source0)._b;
      GoalIr.Cond _12_y = _11___mcc_h6;
      GoalIr.Cond _13_x = _10___mcc_h5;
      if (pos) {
        return NC.create_NOr(__default.Nnf(_13_x, true), __default.Nnf(_12_y, true));
      } else {
        return NC.create_NAnd(__default.Nnf(_13_x, false), __default.Nnf(_12_y, false));
      }
    } else {
      GoalIr.Cond _14___mcc_h7 = ((GoalIr.Cond_Not)_source0)._c;
      GoalIr.Cond _15_x = _14___mcc_h7;
      return __default.Nnf(_15_x, !(pos));
    }
  }
  public static java.math.BigInteger ProhOneP(LProh p, GoalIr.Act a, GoalIr.Hist h)
  {
    java.math.BigInteger _0_m = GoalIr.__default.AndK(GoalIr.__default.B2T(((p).dtor_verbs()).contains((a).dtor_verb())), GoalIr.__default.AndK(GoalIr.__default.B2T(GoalIr.__default.ResOk((p).dtor_res(), (a).dtor_res())), __default.EvalN((p).dtor_cond(), a, h)));
    if (java.util.Objects.equals(_0_m, GoalIr.__default.KT())) {
      return GoalIr.__default.Deny();
    } else if (java.util.Objects.equals(_0_m, GoalIr.__default.KU())) {
      return GoalIr.__default.Escalate();
    } else {
      return GoalIr.__default.Allow();
    }
  }
  public static java.math.BigInteger ProhDecP(dafny.DafnySequence<? extends LProh> ps, GoalIr.Act a, GoalIr.Hist h)
  {
    if ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) {
      return GoalIr.__default.Allow();
    } else {
      return GoalIr.__default.MeetD(__default.ProhOneP(((LProh)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), a, h), __default.ProhDecP((ps).drop(java.math.BigInteger.ONE), a, h));
    }
  }
  public static java.math.BigInteger EscDecP(dafny.DafnySequence<? extends NC> cs, GoalIr.Act a, GoalIr.Hist h)
  {
    if ((java.math.BigInteger.valueOf((cs).length())).signum() == 0) {
      return GoalIr.__default.Allow();
    } else {
      return GoalIr.__default.MeetD(GoalIr.__default.EscOne(__default.EvalN(((NC)(java.lang.Object)((cs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), a, h)), __default.EscDecP((cs).drop(java.math.BigInteger.ONE), a, h));
    }
  }
  public static java.math.BigInteger CeilOne(LCeil c, dafny.DafnySequence<? extends dafny.CodePoint> gid, GoalIr.Act a, GoalIr.Hist h)
  {
    if (GoalIr.__default.AppliesL((c).dtor_sel(), gid, (a).dtor_verb())) {
      return GoalIr.__default.BoundStat((c).dtor_core(), (c).dtor_sel(), a, h);
    } else {
      return GoalIr.__default.Allow();
    }
  }
  public static java.math.BigInteger CeilsDecP(dafny.DafnySequence<? extends LCeil> cs, dafny.DafnySequence<? extends dafny.CodePoint> gid, GoalIr.Act a, GoalIr.Hist h)
  {
    if ((java.math.BigInteger.valueOf((cs).length())).signum() == 0) {
      return GoalIr.__default.Allow();
    } else {
      return GoalIr.__default.MeetD(__default.CeilOne(((LCeil)(java.lang.Object)((cs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), gid, a, h), __default.CeilsDecP((cs).drop(java.math.BigInteger.ONE), gid, a, h));
    }
  }
  public static java.math.BigInteger PredMatch(LPred p, GoalIr.Delegation dg, GoalIr.Act a, GoalIr.Hist h)
  {
    return GoalIr.__default.AndK(GoalIr.__default.B2T((((a).dtor_verb()).equals((p).dtor_verb())) && (GoalIr.__default.DelegOk(dg, (p).dtor_gid(), a))), GoalIr.__default.AndK(GoalIr.__default.B2T(GoalIr.__default.ResOk((p).dtor_res(), (a).dtor_res())), __default.EvalN((p).dtor_cond(), a, h)));
  }
  public static java.math.BigInteger PredDec(LPred p, dafny.DafnySequence<? extends LCeil> ceils, GoalIr.Delegation dg, GoalIr.Act a, GoalIr.Hist h)
  {
    return GoalIr.__default.MeetD(GoalIr.__default.DecOfTri(__default.PredMatch(p, dg, a, h)), __default.CeilsDecP(ceils, (p).dtor_gid(), a, h));
  }
  public static java.math.BigInteger PredsDecP(dafny.DafnySequence<? extends LPred> ps, dafny.DafnySequence<? extends LCeil> ceils, GoalIr.Delegation dg, GoalIr.Act a, GoalIr.Hist h)
  {
    if ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) {
      return GoalIr.__default.Deny();
    } else {
      return GoalIr.__default.JoinD(__default.PredDec(((LPred)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), ceils, dg, a, h), __default.PredsDecP((ps).drop(java.math.BigInteger.ONE), ceils, dg, a, h));
    }
  }
  public static java.math.BigInteger DP(Pol p, GoalIr.Act a, GoalIr.Hist h)
  {
    return GoalIr.__default.MeetD(GoalIr.__default.ValidityDec((p).dtor_validity(), (p).dtor_deleg(), a, h), GoalIr.__default.MeetD(__default.ProhDecP((p).dtor_prohs(), a, h), GoalIr.__default.MeetD(__default.EscDecP((p).dtor_escs(), a, h), __default.PredsDecP((p).dtor_preds(), (p).dtor_ceils(), (p).dtor_deleg(), a, h))));
  }
  public static dafny.DafnySequence<? extends LPred> LowerGrants(GoalIr.Ontology ont, dafny.DafnySequence<? extends GoalIr.Grant> gs)
  {
    dafny.DafnySequence<? extends LPred> _0___accumulator = dafny.DafnySequence.<LPred> empty(LPred._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((gs).length())).signum() == 0) {
        return dafny.DafnySequence.<LPred>concatenate(_0___accumulator, dafny.DafnySequence.<LPred> empty(LPred._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<LPred>concatenate(_0___accumulator, dafny.DafnySequence.<LPred> of(LPred._typeDescriptor(), LPred.create((((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_gid(), (((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_verb(), GoalIr.__default.ResolveSel(ont, (((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_res()), __default.Nnf((((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_cond(), true))));
        GoalIr.Ontology _in0 = ont;
        dafny.DafnySequence<? extends GoalIr.Grant> _in1 = (gs).drop(java.math.BigInteger.ONE);
        ont = _in0;
        gs = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends LProh> LowerProhs(GoalIr.Ontology ont, dafny.DafnySequence<? extends GoalIr.Prohibit> ps)
  {
    dafny.DafnySequence<? extends LProh> _0___accumulator = dafny.DafnySequence.<LProh> empty(LProh._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) {
        return dafny.DafnySequence.<LProh>concatenate(_0___accumulator, dafny.DafnySequence.<LProh> empty(LProh._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<LProh>concatenate(_0___accumulator, dafny.DafnySequence.<LProh> of(LProh._typeDescriptor(), LProh.create((((GoalIr.Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_pid(), GoalIr.__default.ProhVerbs(ont, (((GoalIr.Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_target()), GoalIr.__default.ResolveSel(ont, (((GoalIr.Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_res()), __default.Nnf((((GoalIr.Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_cond(), true))));
        GoalIr.Ontology _in0 = ont;
        dafny.DafnySequence<? extends GoalIr.Prohibit> _in1 = (ps).drop(java.math.BigInteger.ONE);
        ont = _in0;
        ps = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends LCeil> LowerBounds(GoalIr.Ontology ont, dafny.DafnySequence<? extends GoalIr.Bound> bs)
  {
    dafny.DafnySequence<? extends LCeil> _0___accumulator = dafny.DafnySequence.<LCeil> empty(LCeil._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((bs).length())).signum() == 0) {
        return dafny.DafnySequence.<LCeil>concatenate(_0___accumulator, dafny.DafnySequence.<LCeil> empty(LCeil._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<LCeil>concatenate(_0___accumulator, dafny.DafnySequence.<LCeil> of(LCeil._typeDescriptor(), LCeil.create((((GoalIr.Bound)(java.lang.Object)((bs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_bid(), GoalIr.__default.ResolveBSel(ont, (((GoalIr.Bound)(java.lang.Object)((bs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_sel()), (((GoalIr.Bound)(java.lang.Object)((bs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_core())));
        GoalIr.Ontology _in0 = ont;
        dafny.DafnySequence<? extends GoalIr.Bound> _in1 = (bs).drop(java.math.BigInteger.ONE);
        ont = _in0;
        bs = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends NC> LowerEscs(dafny.DafnySequence<? extends GoalIr.Cond> cs) {
    dafny.DafnySequence<? extends NC> _0___accumulator = dafny.DafnySequence.<NC> empty(NC._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((cs).length())).signum() == 0) {
        return dafny.DafnySequence.<NC>concatenate(_0___accumulator, dafny.DafnySequence.<NC> empty(NC._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<NC>concatenate(_0___accumulator, dafny.DafnySequence.<NC> of(NC._typeDescriptor(), __default.Nnf(((GoalIr.Cond)(java.lang.Object)((cs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), true)));
        dafny.DafnySequence<? extends GoalIr.Cond> _in0 = (cs).drop(java.math.BigInteger.ONE);
        cs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static Pol Lower(GoalIr.Ontology ont, GoalIr.Goal g)
  {
    return Pol.create(__default.LowerGrants(ont, (g).dtor_grants()), __default.LowerProhs(ont, (g).dtor_prohibits()), __default.LowerBounds(ont, (g).dtor_bounds()), __default.LowerEscs((g).dtor_escalateOn()), (g).dtor_validity(), (g).dtor_deleg());
  }
  public static boolean DependsOn(dafny.DafnySequence<? extends GoalIr.Hole> hs, dafny.DafnySequence<? extends dafny.CodePoint> gid)
  {
    return ((java.math.BigInteger.valueOf((hs).length())).signum() == 1) && ((((((GoalIr.Hole)(java.lang.Object)((hs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_global()) || (((((GoalIr.Hole)(java.lang.Object)((hs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_affects()).contains(gid))) || (__default.DependsOn((hs).drop(java.math.BigInteger.ONE), gid)));
  }
  public static dafny.DafnySequence<? extends GoalIr.Grant> StripGrants(dafny.DafnySequence<? extends GoalIr.Hole> hs, dafny.DafnySequence<? extends GoalIr.Grant> gs)
  {
    dafny.DafnySequence<? extends GoalIr.Grant> _0___accumulator = dafny.DafnySequence.<GoalIr.Grant> empty(GoalIr.Grant._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((gs).length())).signum() == 0) {
        return dafny.DafnySequence.<GoalIr.Grant>concatenate(_0___accumulator, dafny.DafnySequence.<GoalIr.Grant> empty(GoalIr.Grant._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<GoalIr.Grant>concatenate(_0___accumulator, ((__default.DependsOn(hs, (((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_gid())) ? (dafny.DafnySequence.<GoalIr.Grant> empty(GoalIr.Grant._typeDescriptor())) : (dafny.DafnySequence.<GoalIr.Grant> of(GoalIr.Grant._typeDescriptor(), ((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))))));
        dafny.DafnySequence<? extends GoalIr.Hole> _in0 = hs;
        dafny.DafnySequence<? extends GoalIr.Grant> _in1 = (gs).drop(java.math.BigInteger.ONE);
        hs = _in0;
        gs = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static GoalIr.Goal Strip(GoalIr.Goal g) {
    GoalIr.Goal _0_dt__update__tmp_h0 = g;
    dafny.DafnySequence<? extends GoalIr.Hole> _1_dt__update_hholes_h0 = dafny.DafnySequence.<GoalIr.Hole> empty(GoalIr.Hole._typeDescriptor());
    dafny.DafnySequence<? extends GoalIr.Grant> _2_dt__update_hgrants_h0 = __default.StripGrants((g).dtor_holes(), (g).dtor_grants());
    return GoalIr.Goal.create((_0_dt__update__tmp_h0).dtor_v(), (_0_dt__update__tmp_h0).dtor_principal(), (_0_dt__update__tmp_h0).dtor_ontDigest(), (_0_dt__update__tmp_h0).dtor_nlDigest(), (_0_dt__update__tmp_h0).dtor_sources(), _2_dt__update_hgrants_h0, (_0_dt__update__tmp_h0).dtor_prohibits(), (_0_dt__update__tmp_h0).dtor_bounds(), (_0_dt__update__tmp_h0).dtor_validity(), (_0_dt__update__tmp_h0).dtor_deleg(), (_0_dt__update__tmp_h0).dtor_escalateOn(), (_0_dt__update__tmp_h0).dtor_wildcardAck(), _1_dt__update_hholes_h0);
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> BadGrants(GoalIr.Ontology ont, GoalIr.Goal g, dafny.DafnySequence<? extends GoalIr.Grant> gs)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((gs).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, ((GoalIr.__default.GrantOk(ont, g, ((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((GoalIr.Grant)(java.lang.Object)((gs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_gid()))));
        GoalIr.Ontology _in0 = ont;
        GoalIr.Goal _in1 = g;
        dafny.DafnySequence<? extends GoalIr.Grant> _in2 = (gs).drop(java.math.BigInteger.ONE);
        ont = _in0;
        g = _in1;
        gs = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> BadProhibits(GoalIr.Ontology ont, dafny.DafnySequence<? extends GoalIr.Prohibit> ps)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, ((GoalIr.__default.ProhibitOk(ont, ((GoalIr.Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((GoalIr.Prohibit)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_pid()))));
        GoalIr.Ontology _in0 = ont;
        dafny.DafnySequence<? extends GoalIr.Prohibit> _in1 = (ps).drop(java.math.BigInteger.ONE);
        ont = _in0;
        ps = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> BadBounds(GoalIr.Ontology ont, GoalIr.Goal g, dafny.DafnySequence<? extends GoalIr.Bound> bs)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((bs).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, ((GoalIr.__default.BoundOk(ont, g, ((GoalIr.Bound)(java.lang.Object)((bs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((GoalIr.Bound)(java.lang.Object)((bs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_bid()))));
        GoalIr.Ontology _in0 = ont;
        GoalIr.Goal _in1 = g;
        dafny.DafnySequence<? extends GoalIr.Bound> _in2 = (bs).drop(java.math.BigInteger.ONE);
        ont = _in0;
        g = _in1;
        bs = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> BadHoles(GoalIr.Goal g, dafny.DafnySequence<? extends GoalIr.Hole> hs)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((hs).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, ((GoalIr.__default.HoleOk(g, ((GoalIr.Hole)(java.lang.Object)((hs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))))) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((GoalIr.Hole)(java.lang.Object)((hs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_hid()))));
        GoalIr.Goal _in0 = g;
        dafny.DafnySequence<? extends GoalIr.Hole> _in1 = (hs).drop(java.math.BigInteger.ONE);
        g = _in0;
        hs = _in1;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> TypeReasons(GoalIr.Ontology ont, GoalIr.Goal g)
  {
    return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(((GoalIr.__default.Sorted4(g)) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("not_canonical_order")))), (((java.math.BigInteger.valueOf((__default.BadGrants(ont, g, (g).dtor_grants())).length())).signum() == 0) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("ill_typed_grant"))))), (((java.math.BigInteger.valueOf((__default.BadProhibits(ont, (g).dtor_prohibits())).length())).signum() == 0) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("ill_typed_prohibit"))))), (((java.math.BigInteger.valueOf((__default.BadBounds(ont, g, (g).dtor_bounds())).length())).signum() == 0) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("ill_typed_bound"))))), ((GoalIr.__default.EscsTyped(ont, g)) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("ill_typed_escalation"))))), ((GoalIr.__default.ValidityOk((g).dtor_validity(), (g).dtor_deleg(), g)) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("bad_validity_or_delegation"))))), (((java.math.BigInteger.valueOf((__default.BadHoles(g, (g).dtor_holes())).length())).signum() == 0) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), dafny.DafnySequence.asUnicodeString("bad_hole")))));
  }
  public static CResult Compile(GoalIr.Ontology ont, GoalIr.Goal g)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0_rs = __default.TypeReasons(ont, g);
    if ((java.math.BigInteger.valueOf((_0_rs).length())).signum() == 1) {
      return CResult.create_CEscalate(_0_rs);
    } else {
      return CResult.create_Compiled(__default.Lower(ont, __default.Strip(g)));
    }
  }
  public static boolean ResNarrows(GoalIr.ResPat p2, GoalIr.ResPat p1)
  {
    return ((p1).is_PStar()) || ((((p2).is_PSet()) && ((p1).is_PSet())) && (((dafny.Function2<GoalIr.ResPat, GoalIr.ResPat, Boolean>)(_0_p2, _1_p1) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_0_p2).dtor_ids()).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf(((_0_p2).dtor_ids()).length())) < 0)) || (((_1_p1).dtor_ids()).contains(((dafny.DafnySequence<? extends dafny.CodePoint>)(java.lang.Object)(((_0_p2).dtor_ids()).select(dafny.Helpers.toInt((_2_i)))))));
    }));}).apply(p2, p1)));
  }
  public static boolean CondNarrows(GoalIr.Cond c2, GoalIr.Cond c1)
  {
    return (java.util.Objects.equals(c2, c1)) || (((c2).is_And()) && ((java.util.Objects.equals((c2).dtor_a(), c1)) || (java.util.Objects.equals((c2).dtor_b(), c1))));
  }
  public static boolean GrantNarrows(GoalIr.Ontology ont, GoalIr.Grant g2, GoalIr.Grant g1)
  {
    return (((((g2).dtor_gid()).equals((g1).dtor_gid())) && (((g2).dtor_verb()).equals((g1).dtor_verb()))) && (__default.ResNarrows(GoalIr.__default.ResolveSel(ont, (g2).dtor_res()), GoalIr.__default.ResolveSel(ont, (g1).dtor_res())))) && (__default.CondNarrows((g2).dtor_cond(), (g1).dtor_cond()));
  }
  public static <__T> boolean SubsetOf(dafny.TypeDescriptor<__T> _td___T, dafny.DafnySequence<? extends __T> xs, dafny.DafnySequence<? extends __T> ys)
  {
    return ((dafny.Function2<dafny.DafnySequence<? extends __T>, dafny.DafnySequence<? extends __T>, Boolean>)(_0_xs, _1_ys) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf((_0_xs).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _2_i = (java.math.BigInteger)_forall_var_0;
      return !(((_2_i).signum() != -1) && ((_2_i).compareTo(java.math.BigInteger.valueOf((_0_xs).length())) < 0)) || ((_1_ys).contains(((__T)(java.lang.Object)((_0_xs).select(dafny.Helpers.toInt((_2_i)))))));
    }));}).apply(xs, ys);
  }
  public static boolean Refines(GoalIr.Ontology ont, GoalIr.Goal g2, GoalIr.Goal g1)
  {
    return ((((((((((dafny.Function3<GoalIr.Goal, GoalIr.Goal, GoalIr.Ontology, Boolean>)(_0_g2, _1_g1, _2_ont) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_0_g2).dtor_grants()).length())), true, ((_forall_var_0_boxed0) -> {
      java.math.BigInteger _forall_var_0 = ((java.math.BigInteger)(java.lang.Object)(_forall_var_0_boxed0));
      java.math.BigInteger _3_i = (java.math.BigInteger)_forall_var_0;
      return !(((_3_i).signum() != -1) && ((_3_i).compareTo(java.math.BigInteger.valueOf(((_0_g2).dtor_grants()).length())) < 0)) || (((dafny.Function4<GoalIr.Goal, GoalIr.Ontology, GoalIr.Goal, java.math.BigInteger, Boolean>)(_4_g1, _5_ont, _6_g2, _7_i) -> {return dafny.Helpers.Quantifier(dafny.Helpers.IntegerRange(java.math.BigInteger.ZERO, java.math.BigInteger.valueOf(((_4_g1).dtor_grants()).length())), false, ((_exists_var_0_boxed0) -> {
        java.math.BigInteger _exists_var_0 = ((java.math.BigInteger)(java.lang.Object)(_exists_var_0_boxed0));
        java.math.BigInteger _8_j = (java.math.BigInteger)_exists_var_0;
        return (((_8_j).signum() != -1) && ((_8_j).compareTo(java.math.BigInteger.valueOf(((_4_g1).dtor_grants()).length())) < 0)) && (__default.GrantNarrows(_5_ont, ((GoalIr.Grant)(java.lang.Object)(((_6_g2).dtor_grants()).select(dafny.Helpers.toInt((_7_i))))), ((GoalIr.Grant)(java.lang.Object)(((_4_g1).dtor_grants()).select(dafny.Helpers.toInt((_8_j)))))));
      }));}).apply(_1_g1, _2_ont, _0_g2, _3_i));
    }));}).apply(g2, g1, ont)) && (__default.<GoalIr.Prohibit>SubsetOf(GoalIr.Prohibit._typeDescriptor(), (g1).dtor_prohibits(), (g2).dtor_prohibits()))) && (__default.<GoalIr.Bound>SubsetOf(GoalIr.Bound._typeDescriptor(), (g1).dtor_bounds(), (g2).dtor_bounds()))) && (__default.<GoalIr.Cond>SubsetOf(GoalIr.Cond._typeDescriptor(), (g1).dtor_escalateOn(), (g2).dtor_escalateOn()))) && ((((g2).dtor_validity()).dtor_notBefore()).compareTo(((g1).dtor_validity()).dtor_notBefore()) >= 0)) && ((((g2).dtor_validity()).dtor_notAfter()).compareTo(((g1).dtor_validity()).dtor_notAfter()) <= 0)) && (((((g1).dtor_validity()).dtor_maxIdle()).signum() != 1) || (((((g2).dtor_validity()).dtor_maxIdle()).signum() == 1) && ((((g2).dtor_validity()).dtor_maxIdle()).compareTo(((g1).dtor_validity()).dtor_maxIdle()) <= 0)))) && ((((g2).dtor_deleg()).dtor_maxDepth()).compareTo(((g1).dtor_deleg()).dtor_maxDepth()) <= 0)) && (__default.<dafny.DafnySequence<? extends dafny.CodePoint>>SubsetOf(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), ((g2).dtor_deleg()).dtor_mayTouch(), ((g1).dtor_deleg()).dtor_mayTouch()));
  }
  public static java.math.BigInteger BoundOne(GoalIr.Ontology ont, GoalIr.Bound b, dafny.DafnySequence<? extends dafny.CodePoint> gid, GoalIr.Act a, GoalIr.Hist h)
  {
    GoalIr.LSel _0_s = GoalIr.__default.ResolveBSel(ont, (b).dtor_sel());
    if (GoalIr.__default.AppliesL(_0_s, gid, (a).dtor_verb())) {
      return GoalIr.__default.BoundStat((b).dtor_core(), _0_s, a, h);
    } else {
      return GoalIr.__default.Allow();
    }
  }
  public static boolean Refines2V(GoalIr.Goal g2, GoalIr.Goal g1)
  {
    return ((((((g2).dtor_validity()).dtor_notBefore()).compareTo(((g1).dtor_validity()).dtor_notBefore()) >= 0) && ((((g2).dtor_validity()).dtor_notAfter()).compareTo(((g1).dtor_validity()).dtor_notAfter()) <= 0)) && (((((g1).dtor_validity()).dtor_maxIdle()).signum() != 1) || (((((g2).dtor_validity()).dtor_maxIdle()).signum() == 1) && ((((g2).dtor_validity()).dtor_maxIdle()).compareTo(((g1).dtor_validity()).dtor_maxIdle()) <= 0)))) && ((((g2).dtor_deleg()).dtor_maxDepth()).compareTo(((g1).dtor_deleg()).dtor_maxDepth()) <= 0);
  }
  @Override
  public java.lang.String toString() {
    return "GoalCompile._default";
  }
}
