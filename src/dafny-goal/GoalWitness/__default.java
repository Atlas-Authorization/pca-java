// Class __default
// Dafny class __default compiled into Java
package GoalWitness;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> Applicable(dafny.DafnySequence<? extends GoalCompile.LCeil> cs, dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends dafny.CodePoint> verb)
  {
    dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR));
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((cs).length())).signum() == 0) {
        return dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)));
      } else {
        _0___accumulator = dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>>concatenate(_0___accumulator, ((GoalIr.__default.AppliesL((((GoalCompile.LCeil)(java.lang.Object)((cs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_sel(), gid, verb)) ? (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> of(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), (((GoalCompile.LCeil)(java.lang.Object)((cs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_bid())) : (dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR)))));
        dafny.DafnySequence<? extends GoalCompile.LCeil> _in0 = (cs).drop(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends dafny.CodePoint> _in1 = gid;
        dafny.DafnySequence<? extends dafny.CodePoint> _in2 = verb;
        cs = _in0;
        gid = _in1;
        verb = _in2;
        continue TAIL_CALL_START;
      }
    }
  }
  public static GoalIr.Option<GoalCompile.LPred> FindAllow(dafny.DafnySequence<? extends GoalCompile.LPred> ps, dafny.DafnySequence<? extends GoalCompile.LCeil> ceils, GoalIr.Delegation dg, GoalIr.Act a, GoalIr.Hist h)
  {
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((ps).length())).signum() == 0) {
        return GoalIr.Option.<GoalCompile.LPred>create_None(GoalCompile.LPred._typeDescriptor());
      } else if (java.util.Objects.equals(GoalCompile.__default.PredDec(((GoalCompile.LPred)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), ceils, dg, a, h), GoalIr.__default.Allow())) {
        return GoalIr.Option.<GoalCompile.LPred>create_Some(GoalCompile.LPred._typeDescriptor(), ((GoalCompile.LPred)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))));
      } else {
        dafny.DafnySequence<? extends GoalCompile.LPred> _in0 = (ps).drop(java.math.BigInteger.ONE);
        dafny.DafnySequence<? extends GoalCompile.LCeil> _in1 = ceils;
        GoalIr.Delegation _in2 = dg;
        GoalIr.Act _in3 = a;
        GoalIr.Hist _in4 = h;
        ps = _in0;
        ceils = _in1;
        dg = _in2;
        a = _in3;
        h = _in4;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.Tuple2<java.math.BigInteger, Wit> DecideW(GoalCompile.Pol p, GoalIr.Act a, GoalIr.Hist h)
  {
    java.math.BigInteger _0_d = GoalCompile.__default.DP(p, a, h);
    if (java.util.Objects.equals(_0_d, GoalIr.__default.Allow())) {
      GoalIr.Option<GoalCompile.LPred> _source0 = __default.FindAllow((p).dtor_preds(), (p).dtor_ceils(), (p).dtor_deleg(), a, h);
      if (_source0.is_None()) {
        return dafny.Tuple2.<java.math.BigInteger, Wit>create(GoalIr.__default.Deny(), Wit.create(dafny.DafnySequence.asUnicodeString(""), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))));
      } else {
        GoalCompile.LPred _1___mcc_h0 = ((GoalIr.Option_Some<GoalCompile.LPred>)_source0)._v;
        GoalCompile.LPred _2_pr = _1___mcc_h0;
        return dafny.Tuple2.<java.math.BigInteger, Wit>create(GoalIr.__default.Allow(), Wit.create((_2_pr).dtor_gid(), __default.Applicable((p).dtor_ceils(), (_2_pr).dtor_gid(), (a).dtor_verb())));
      }
    } else {
      return dafny.Tuple2.<java.math.BigInteger, Wit>create(_0_d, Wit.create(dafny.DafnySequence.asUnicodeString(""), dafny.DafnySequence.<dafny.DafnySequence<? extends dafny.CodePoint>> empty(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR))));
    }
  }
  public static boolean AnyPredAllows(dafny.DafnySequence<? extends GoalCompile.LPred> ps, dafny.DafnySequence<? extends dafny.CodePoint> gid, dafny.DafnySequence<? extends GoalCompile.LCeil> ceils, GoalIr.Delegation dg, GoalIr.Act a, GoalIr.Hist h)
  {
    return ((java.math.BigInteger.valueOf((ps).length())).signum() == 1) && (((((((GoalCompile.LPred)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_gid()).equals(gid)) && (java.util.Objects.equals(GoalCompile.__default.PredDec(((GoalCompile.LPred)(java.lang.Object)((ps).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), ceils, dg, a, h), GoalIr.__default.Allow()))) || (__default.AnyPredAllows((ps).drop(java.math.BigInteger.ONE), gid, ceils, dg, a, h)));
  }
  public static boolean VerifyWitness(GoalCompile.Pol p, GoalIr.Act a, GoalIr.Hist h, Wit w)
  {
    return ((((java.util.Objects.equals(GoalIr.__default.ValidityDec((p).dtor_validity(), (p).dtor_deleg(), a, h), GoalIr.__default.Allow())) && (java.util.Objects.equals(GoalCompile.__default.ProhDecP((p).dtor_prohs(), a, h), GoalIr.__default.Allow()))) && (java.util.Objects.equals(GoalCompile.__default.EscDecP((p).dtor_escs(), a, h), GoalIr.__default.Allow()))) && (__default.AnyPredAllows((p).dtor_preds(), (w).dtor_gid(), (p).dtor_ceils(), (p).dtor_deleg(), a, h))) && (((w).dtor_bids()).equals(__default.Applicable((p).dtor_ceils(), (w).dtor_gid(), (a).dtor_verb())));
  }
  public static boolean PepAllows(java.math.BigInteger d, GoalIr.Option<Answer> ans, dafny.DafnySequence<? extends dafny.CodePoint> pd, dafny.DafnySequence<? extends dafny.CodePoint> ad, dafny.DafnySequence<? extends dafny.CodePoint> hh)
  {
    return (java.util.Objects.equals(d, GoalIr.__default.Allow())) || ((((((java.util.Objects.equals(d, GoalIr.__default.Escalate())) && ((ans).is_Some())) && (((ans).dtor_v()).dtor_sigOk())) && ((((ans).dtor_v()).dtor_policyDigest()).equals(pd))) && ((((ans).dtor_v()).dtor_actionDigest()).equals(ad))) && ((((ans).dtor_v()).dtor_histHead()).equals(hh)));
  }
  @Override
  public java.lang.String toString() {
    return "GoalWitness._default";
  }
}
