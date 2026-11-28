// Class __default
// Dafny class __default compiled into Java
package GoalApi;

@SuppressWarnings({"unchecked", "deprecation"})
public class __default {
  public __default() {
  }
  public static GoalRender.PR<GoalIr.ParamDecl> DecParamDecl(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(500L))))) {
      return GoalRender.PR.<GoalIr.ParamDecl>create_Fail(GoalIr.ParamDecl._typeDescriptor());
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = GoalRender.__default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<GoalIr.ParamDecl>create_Fail(GoalIr.ParamDecl._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_p = _0___mcc_h0;
        GoalRender.PR<GoalIr.Ty> _source1 = GoalRender.__default.DecTy(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<GoalIr.ParamDecl>create_Fail(GoalIr.ParamDecl._typeDescriptor());
        } else {
          GoalIr.Ty _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.Ty>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.Ty>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          GoalIr.Ty _7_ty = _4___mcc_h2;
          return GoalRender.PR.<GoalIr.ParamDecl>create_Ok(GoalIr.ParamDecl._typeDescriptor(), GoalIr.ParamDecl.create(_3_p, _7_ty), _6_r2);
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.ParamDecl>> DecParamDeclsElems(dafny.DafnySequence<? extends GoalRender.Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.ParamDecl>>create_Ok(dafny.DafnySequence.<GoalIr.ParamDecl>_typeDescriptor(GoalIr.ParamDecl._typeDescriptor()), dafny.DafnySequence.<GoalIr.ParamDecl> empty(GoalIr.ParamDecl._typeDescriptor()), ts);
    } else {
      GoalRender.PR<GoalIr.ParamDecl> _source0 = __default.DecParamDecl(ts);
      if (_source0.is_Fail()) {
        return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.ParamDecl>>create_Fail(dafny.DafnySequence.<GoalIr.ParamDecl>_typeDescriptor(GoalIr.ParamDecl._typeDescriptor()));
      } else {
        GoalIr.ParamDecl _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.ParamDecl>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.ParamDecl>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r = _1___mcc_h1;
        GoalIr.ParamDecl _3_x = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends GoalIr.ParamDecl>> _source1 = __default.DecParamDeclsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.ParamDecl>>create_Fail(dafny.DafnySequence.<GoalIr.ParamDecl>_typeDescriptor(GoalIr.ParamDecl._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.ParamDecl> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ParamDecl>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ParamDecl>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.ParamDecl> _7_xs = _4___mcc_h2;
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.ParamDecl>>create_Ok(dafny.DafnySequence.<GoalIr.ParamDecl>_typeDescriptor(GoalIr.ParamDecl._typeDescriptor()), dafny.DafnySequence.<GoalIr.ParamDecl>concatenate(dafny.DafnySequence.<GoalIr.ParamDecl> of(GoalIr.ParamDecl._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.ParamDecl>> DecParamDecls(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecParamDeclsElems((ts).drop(java.math.BigInteger.ONE), (((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.ParamDecl>>create_Fail(dafny.DafnySequence.<GoalIr.ParamDecl>_typeDescriptor(GoalIr.ParamDecl._typeDescriptor()));
    }
  }
  public static GoalRender.PR<GoalIr.VerbDecl> DecVerbDecl(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(501L))))) {
      return GoalRender.PR.<GoalIr.VerbDecl>create_Fail(GoalIr.VerbDecl._typeDescriptor());
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = GoalRender.__default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<GoalIr.VerbDecl>create_Fail(GoalIr.VerbDecl._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_v = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = GoalRender.__default.DecStr(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<GoalIr.VerbDecl>create_Fail(GoalIr.VerbDecl._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends dafny.CodePoint> _7_c = _4___mcc_h2;
          GoalRender.PR<dafny.DafnySequence<? extends GoalIr.ParamDecl>> _source2 = __default.DecParamDecls(_6_r2);
          if (_source2.is_Fail()) {
            return GoalRender.PR.<GoalIr.VerbDecl>create_Fail(GoalIr.VerbDecl._typeDescriptor());
          } else {
            dafny.DafnySequence<? extends GoalIr.ParamDecl> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ParamDecl>>)_source2)._v;
            dafny.DafnySequence<? extends GoalRender.Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.ParamDecl>>)_source2)._rest;
            dafny.DafnySequence<? extends GoalRender.Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnySequence<? extends GoalIr.ParamDecl> _11_ps = _8___mcc_h4;
            return GoalRender.PR.<GoalIr.VerbDecl>create_Ok(GoalIr.VerbDecl._typeDescriptor(), GoalIr.VerbDecl.create(_3_v, _7_c, _11_ps), _10_r3);
          }
        }
      }
    }
  }
  public static GoalRender.PR<GoalIr.RelDecl> DecRelDecl(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(502L))))) {
      return GoalRender.PR.<GoalIr.RelDecl>create_Fail(GoalIr.RelDecl._typeDescriptor());
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = GoalRender.__default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<GoalIr.RelDecl>create_Fail(GoalIr.RelDecl._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_rel = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = GoalRender.__default.DecStr(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<GoalIr.RelDecl>create_Fail(GoalIr.RelDecl._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends dafny.CodePoint> _7_an = _4___mcc_h2;
          GoalRender.PR<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>> _source2 = GoalRender.__default.DecStrs(_6_r2);
          if (_source2.is_Fail()) {
            return GoalRender.PR.<GoalIr.RelDecl>create_Fail(GoalIr.RelDecl._typeDescriptor());
          } else {
            dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source2)._v;
            dafny.DafnySequence<? extends GoalRender.Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>>>)_source2)._rest;
            dafny.DafnySequence<? extends GoalRender.Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _11_ms = _8___mcc_h4;
            return GoalRender.PR.<GoalIr.RelDecl>create_Ok(GoalIr.RelDecl._typeDescriptor(), GoalIr.RelDecl.create(_3_rel, _7_an, _11_ms), _10_r3);
          }
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.VerbDecl>> DecVerbDeclsElems(dafny.DafnySequence<? extends GoalRender.Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.VerbDecl>>create_Ok(dafny.DafnySequence.<GoalIr.VerbDecl>_typeDescriptor(GoalIr.VerbDecl._typeDescriptor()), dafny.DafnySequence.<GoalIr.VerbDecl> empty(GoalIr.VerbDecl._typeDescriptor()), ts);
    } else {
      GoalRender.PR<GoalIr.VerbDecl> _source0 = __default.DecVerbDecl(ts);
      if (_source0.is_Fail()) {
        return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.VerbDecl>>create_Fail(dafny.DafnySequence.<GoalIr.VerbDecl>_typeDescriptor(GoalIr.VerbDecl._typeDescriptor()));
      } else {
        GoalIr.VerbDecl _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.VerbDecl>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.VerbDecl>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r = _1___mcc_h1;
        GoalIr.VerbDecl _3_x = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends GoalIr.VerbDecl>> _source1 = __default.DecVerbDeclsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.VerbDecl>>create_Fail(dafny.DafnySequence.<GoalIr.VerbDecl>_typeDescriptor(GoalIr.VerbDecl._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.VerbDecl> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.VerbDecl>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.VerbDecl>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.VerbDecl> _7_xs = _4___mcc_h2;
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.VerbDecl>>create_Ok(dafny.DafnySequence.<GoalIr.VerbDecl>_typeDescriptor(GoalIr.VerbDecl._typeDescriptor()), dafny.DafnySequence.<GoalIr.VerbDecl>concatenate(dafny.DafnySequence.<GoalIr.VerbDecl> of(GoalIr.VerbDecl._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.VerbDecl>> DecVerbDecls(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecVerbDeclsElems((ts).drop(java.math.BigInteger.ONE), (((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.VerbDecl>>create_Fail(dafny.DafnySequence.<GoalIr.VerbDecl>_typeDescriptor(GoalIr.VerbDecl._typeDescriptor()));
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.RelDecl>> DecRelDeclsElems(dafny.DafnySequence<? extends GoalRender.Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.RelDecl>>create_Ok(dafny.DafnySequence.<GoalIr.RelDecl>_typeDescriptor(GoalIr.RelDecl._typeDescriptor()), dafny.DafnySequence.<GoalIr.RelDecl> empty(GoalIr.RelDecl._typeDescriptor()), ts);
    } else {
      GoalRender.PR<GoalIr.RelDecl> _source0 = __default.DecRelDecl(ts);
      if (_source0.is_Fail()) {
        return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.RelDecl>>create_Fail(dafny.DafnySequence.<GoalIr.RelDecl>_typeDescriptor(GoalIr.RelDecl._typeDescriptor()));
      } else {
        GoalIr.RelDecl _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.RelDecl>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.RelDecl>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r = _1___mcc_h1;
        GoalIr.RelDecl _3_x = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends GoalIr.RelDecl>> _source1 = __default.DecRelDeclsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.RelDecl>>create_Fail(dafny.DafnySequence.<GoalIr.RelDecl>_typeDescriptor(GoalIr.RelDecl._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.RelDecl> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.RelDecl>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.RelDecl>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.RelDecl> _7_xs = _4___mcc_h2;
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.RelDecl>>create_Ok(dafny.DafnySequence.<GoalIr.RelDecl>_typeDescriptor(GoalIr.RelDecl._typeDescriptor()), dafny.DafnySequence.<GoalIr.RelDecl>concatenate(dafny.DafnySequence.<GoalIr.RelDecl> of(GoalIr.RelDecl._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.RelDecl>> DecRelDecls(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecRelDeclsElems((ts).drop(java.math.BigInteger.ONE), (((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.RelDecl>>create_Fail(dafny.DafnySequence.<GoalIr.RelDecl>_typeDescriptor(GoalIr.RelDecl._typeDescriptor()));
    }
  }
  public static GoalRender.PR<GoalIr.Ontology> DecOntology(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(510L))))) {
      return GoalRender.PR.<GoalIr.Ontology>create_Fail(GoalIr.Ontology._typeDescriptor());
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends GoalIr.VerbDecl>> _source0 = __default.DecVerbDecls((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<GoalIr.Ontology>create_Fail(GoalIr.Ontology._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends GoalIr.VerbDecl> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.VerbDecl>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.VerbDecl>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends GoalIr.VerbDecl> _3_vs = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends GoalIr.RelDecl>> _source1 = __default.DecRelDecls(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<GoalIr.Ontology>create_Fail(GoalIr.Ontology._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends GoalIr.RelDecl> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.RelDecl>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.RelDecl>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.RelDecl> _7_rs = _4___mcc_h2;
          return GoalRender.PR.<GoalIr.Ontology>create_Ok(GoalIr.Ontology._typeDescriptor(), GoalIr.Ontology.create(_3_vs, _7_rs), _6_r2);
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>> DecParamEntries(dafny.DafnySequence<? extends GoalRender.Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>create_Ok(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.V._typeDescriptor()), dafny.DafnyMap.fromElements((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>[])new dafny.Tuple2[]{ }), ts);
    } else if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(520L))))) {
      return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.V._typeDescriptor()));
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = GoalRender.__default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.V._typeDescriptor()));
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_k = _0___mcc_h0;
        GoalRender.PR<GoalIr.V> _source1 = GoalRender.__default.DecV(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.V._typeDescriptor()));
        } else {
          GoalIr.V _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.V>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.V>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          GoalIr.V _7_v = _4___mcc_h2;
          GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>> _source2 = __default.DecParamEntries(_6_r2, (n).subtract(java.math.BigInteger.ONE));
          if (_source2.is_Fail()) {
            return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.V._typeDescriptor()));
          } else {
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>)_source2)._v;
            dafny.DafnySequence<? extends GoalRender.Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>)_source2)._rest;
            dafny.DafnySequence<? extends GoalRender.Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V> _11_m = _8___mcc_h4;
            return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>create_Ok(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.V._typeDescriptor()), dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>update(_11_m, _3_k, _7_v), _10_r3);
          }
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>> DecParams(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecParamEntries((ts).drop(java.math.BigInteger.ONE), (((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.V>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.V._typeDescriptor()));
    }
  }
  public static GoalRender.PR<GoalIr.Act> DecAct(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(530L))))) {
      return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = GoalRender.__default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_verb = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source1 = GoalRender.__default.DecStr(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
        } else {
          dafny.DafnySequence<? extends dafny.CodePoint> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends dafny.CodePoint> _7_res = _4___mcc_h2;
          GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>> _source2 = __default.DecParams(_6_r2);
          if (_source2.is_Fail()) {
            return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
          } else {
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>)_source2)._v;
            dafny.DafnySequence<? extends GoalRender.Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V>>)_source2)._rest;
            dafny.DafnySequence<? extends GoalRender.Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.V> _11_ps = _8___mcc_h4;
            GoalRender.PR<java.math.BigInteger> _source3 = GoalRender.__default.DecInt(_10_r3);
            if (_source3.is_Fail()) {
              return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
            } else {
              java.math.BigInteger _12___mcc_h6 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source3)._v;
              dafny.DafnySequence<? extends GoalRender.Tok> _13___mcc_h7 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source3)._rest;
              dafny.DafnySequence<? extends GoalRender.Tok> _14_r4 = _13___mcc_h7;
              java.math.BigInteger _15_t = _12___mcc_h6;
              GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source4 = GoalRender.__default.DecStr(_14_r4);
              if (_source4.is_Fail()) {
                return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
              } else {
                dafny.DafnySequence<? extends dafny.CodePoint> _16___mcc_h8 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source4)._v;
                dafny.DafnySequence<? extends GoalRender.Tok> _17___mcc_h9 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source4)._rest;
                dafny.DafnySequence<? extends GoalRender.Tok> _18_r5 = _17___mcc_h9;
                dafny.DafnySequence<? extends dafny.CodePoint> _19_sess = _16___mcc_h8;
                GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source5 = GoalRender.__default.DecStr(_18_r5);
                if (_source5.is_Fail()) {
                  return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
                } else {
                  dafny.DafnySequence<? extends dafny.CodePoint> _20___mcc_h10 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source5)._v;
                  dafny.DafnySequence<? extends GoalRender.Tok> _21___mcc_h11 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source5)._rest;
                  dafny.DafnySequence<? extends GoalRender.Tok> _22_r6 = _21___mcc_h11;
                  dafny.DafnySequence<? extends dafny.CodePoint> _23_prin = _20___mcc_h10;
                  GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source6 = GoalRender.__default.DecStr(_22_r6);
                  if (_source6.is_Fail()) {
                    return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
                  } else {
                    dafny.DafnySequence<? extends dafny.CodePoint> _24___mcc_h12 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source6)._v;
                    dafny.DafnySequence<? extends GoalRender.Tok> _25___mcc_h13 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source6)._rest;
                    dafny.DafnySequence<? extends GoalRender.Tok> _26_r7 = _25___mcc_h13;
                    dafny.DafnySequence<? extends dafny.CodePoint> _27_org = _24___mcc_h12;
                    GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source7 = GoalRender.__default.DecStr(_26_r7);
                    if (_source7.is_Fail()) {
                      return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
                    } else {
                      dafny.DafnySequence<? extends dafny.CodePoint> _28___mcc_h14 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source7)._v;
                      dafny.DafnySequence<? extends GoalRender.Tok> _29___mcc_h15 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source7)._rest;
                      dafny.DafnySequence<? extends GoalRender.Tok> _30_r8 = _29___mcc_h15;
                      dafny.DafnySequence<? extends dafny.CodePoint> _31_agent = _28___mcc_h14;
                      GoalRender.PR<java.math.BigInteger> _source8 = GoalRender.__default.DecInt(_30_r8);
                      if (_source8.is_Fail()) {
                        return GoalRender.PR.<GoalIr.Act>create_Fail(GoalIr.Act._typeDescriptor());
                      } else {
                        java.math.BigInteger _32___mcc_h16 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source8)._v;
                        dafny.DafnySequence<? extends GoalRender.Tok> _33___mcc_h17 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source8)._rest;
                        dafny.DafnySequence<? extends GoalRender.Tok> _34_r9 = _33___mcc_h17;
                        java.math.BigInteger _35_depth = _32___mcc_h16;
                        return GoalRender.PR.<GoalIr.Act>create_Ok(GoalIr.Act._typeDescriptor(), GoalIr.Act.create(_3_verb, _7_res, _11_ps, _15_t, _19_sess, _23_prin, _27_org, _31_agent, _35_depth), _34_r9);
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
  public static GoalRender.PR<GoalIr.Adm> DecAdm(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(531L))))) {
      return GoalRender.PR.<GoalIr.Adm>create_Fail(GoalIr.Adm._typeDescriptor());
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = GoalRender.__default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<GoalIr.Adm>create_Fail(GoalIr.Adm._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_gid = _0___mcc_h0;
        GoalRender.PR<GoalIr.Act> _source1 = __default.DecAct(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<GoalIr.Adm>create_Fail(GoalIr.Adm._typeDescriptor());
        } else {
          GoalIr.Act _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.Act>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.Act>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          GoalIr.Act _7_a = _4___mcc_h2;
          return GoalRender.PR.<GoalIr.Adm>create_Ok(GoalIr.Adm._typeDescriptor(), GoalIr.Adm.create(_3_gid, _7_a), _6_r2);
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.Adm>> DecAdmsElems(dafny.DafnySequence<? extends GoalRender.Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.Adm>>create_Ok(dafny.DafnySequence.<GoalIr.Adm>_typeDescriptor(GoalIr.Adm._typeDescriptor()), dafny.DafnySequence.<GoalIr.Adm> empty(GoalIr.Adm._typeDescriptor()), ts);
    } else {
      GoalRender.PR<GoalIr.Adm> _source0 = __default.DecAdm(ts);
      if (_source0.is_Fail()) {
        return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.Adm>>create_Fail(dafny.DafnySequence.<GoalIr.Adm>_typeDescriptor(GoalIr.Adm._typeDescriptor()));
      } else {
        GoalIr.Adm _0___mcc_h0 = ((GoalRender.PR_Ok<GoalIr.Adm>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<GoalIr.Adm>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r = _1___mcc_h1;
        GoalIr.Adm _3_x = _0___mcc_h0;
        GoalRender.PR<dafny.DafnySequence<? extends GoalIr.Adm>> _source1 = __default.DecAdmsElems(_2_r, (n).subtract(java.math.BigInteger.ONE));
        if (_source1.is_Fail()) {
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.Adm>>create_Fail(dafny.DafnySequence.<GoalIr.Adm>_typeDescriptor(GoalIr.Adm._typeDescriptor()));
        } else {
          dafny.DafnySequence<? extends GoalIr.Adm> _4___mcc_h2 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Adm>>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Adm>>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          dafny.DafnySequence<? extends GoalIr.Adm> _7_xs = _4___mcc_h2;
          return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.Adm>>create_Ok(dafny.DafnySequence.<GoalIr.Adm>_typeDescriptor(GoalIr.Adm._typeDescriptor()), dafny.DafnySequence.<GoalIr.Adm>concatenate(dafny.DafnySequence.<GoalIr.Adm> of(GoalIr.Adm._typeDescriptor(), _3_x), _7_xs), _6_r2);
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnySequence<? extends GoalIr.Adm>> DecAdms(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecAdmsElems((ts).drop(java.math.BigInteger.ONE), (((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return GoalRender.PR.<dafny.DafnySequence<? extends GoalIr.Adm>>create_Fail(dafny.DafnySequence.<GoalIr.Adm>_typeDescriptor(GoalIr.Adm._typeDescriptor()));
    }
  }
  public static GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>> DecAggEntries(dafny.DafnySequence<? extends GoalRender.Tok> ts, java.math.BigInteger n)
  {
    if ((n).signum() == 0) {
      return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>create_Ok(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.Q._typeDescriptor()), dafny.DafnyMap.fromElements((dafny.Tuple2<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>[])new dafny.Tuple2[]{ }), ts);
    } else if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(540L))))) {
      return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.Q._typeDescriptor()));
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends dafny.CodePoint>> _source0 = GoalRender.__default.DecStr((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.Q._typeDescriptor()));
      } else {
        dafny.DafnySequence<? extends dafny.CodePoint> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends dafny.CodePoint>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends dafny.CodePoint> _3_k = _0___mcc_h0;
        GoalRender.PR<GoalIr.Q> _source1 = GoalRender.__default.DecQ(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.Q._typeDescriptor()));
        } else {
          GoalIr.Q _4___mcc_h2 = ((GoalRender.PR_Ok<GoalIr.Q>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<GoalIr.Q>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          GoalIr.Q _7_q = _4___mcc_h2;
          GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>> _source2 = __default.DecAggEntries(_6_r2, (n).subtract(java.math.BigInteger.ONE));
          if (_source2.is_Fail()) {
            return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.Q._typeDescriptor()));
          } else {
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>)_source2)._v;
            dafny.DafnySequence<? extends GoalRender.Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>)_source2)._rest;
            dafny.DafnySequence<? extends GoalRender.Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q> _11_m = _8___mcc_h4;
            return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>create_Ok(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.Q._typeDescriptor()), dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>update(_11_m, _3_k, _7_q), _10_r3);
          }
        }
      }
    }
  }
  public static GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>> DecAggs(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if ((((java.math.BigInteger.valueOf((ts).length())).signum() == 1) && ((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).is_TI())) && (((((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i()).signum() != -1)) {
      return __default.DecAggEntries((ts).drop(java.math.BigInteger.ONE), (((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))).dtor_i());
    } else {
      return GoalRender.PR.<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>create_Fail(dafny.DafnyMap.<dafny.DafnySequence<? extends dafny.CodePoint>, GoalIr.Q>_typeDescriptor(dafny.DafnySequence.<dafny.CodePoint>_typeDescriptor(dafny.TypeDescriptor.UNICODE_CHAR), GoalIr.Q._typeDescriptor()));
    }
  }
  public static GoalRender.PR<GoalIr.Hist> DecHist(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    if (((java.math.BigInteger.valueOf((ts).length())).signum() == 0) || (!java.util.Objects.equals(((GoalRender.Tok)(java.lang.Object)((ts).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO))))), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(541L))))) {
      return GoalRender.PR.<GoalIr.Hist>create_Fail(GoalIr.Hist._typeDescriptor());
    } else {
      GoalRender.PR<dafny.DafnySequence<? extends GoalIr.Adm>> _source0 = __default.DecAdms((ts).drop(java.math.BigInteger.ONE));
      if (_source0.is_Fail()) {
        return GoalRender.PR.<GoalIr.Hist>create_Fail(GoalIr.Hist._typeDescriptor());
      } else {
        dafny.DafnySequence<? extends GoalIr.Adm> _0___mcc_h0 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Adm>>)_source0)._v;
        dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<dafny.DafnySequence<? extends GoalIr.Adm>>)_source0)._rest;
        dafny.DafnySequence<? extends GoalRender.Tok> _2_r1 = _1___mcc_h1;
        dafny.DafnySequence<? extends GoalIr.Adm> _3_adms = _0___mcc_h0;
        GoalRender.PR<java.math.BigInteger> _source1 = GoalRender.__default.DecInt(_2_r1);
        if (_source1.is_Fail()) {
          return GoalRender.PR.<GoalIr.Hist>create_Fail(GoalIr.Hist._typeDescriptor());
        } else {
          java.math.BigInteger _4___mcc_h2 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._v;
          dafny.DafnySequence<? extends GoalRender.Tok> _5___mcc_h3 = ((GoalRender.PR_Ok<java.math.BigInteger>)_source1)._rest;
          dafny.DafnySequence<? extends GoalRender.Tok> _6_r2 = _5___mcc_h3;
          java.math.BigInteger _7_last = _4___mcc_h2;
          GoalRender.PR<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>> _source2 = __default.DecAggs(_6_r2);
          if (_source2.is_Fail()) {
            return GoalRender.PR.<GoalIr.Hist>create_Fail(GoalIr.Hist._typeDescriptor());
          } else {
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q> _8___mcc_h4 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>)_source2)._v;
            dafny.DafnySequence<? extends GoalRender.Tok> _9___mcc_h5 = ((GoalRender.PR_Ok<dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q>>)_source2)._rest;
            dafny.DafnySequence<? extends GoalRender.Tok> _10_r3 = _9___mcc_h5;
            dafny.DafnyMap<? extends dafny.DafnySequence<? extends dafny.CodePoint>, ? extends GoalIr.Q> _11_aggs = _8___mcc_h4;
            return GoalRender.PR.<GoalIr.Hist>create_Ok(GoalIr.Hist._typeDescriptor(), GoalIr.Hist.create(_3_adms, _7_last, _11_aggs), _10_r3);
          }
        }
      }
    }
  }
  public static <__T> GoalIr.Option<__T> Whole(dafny.TypeDescriptor<__T> _td___T, GoalRender.PR<__T> r)
  {
    GoalRender.PR<__T> _source0 = r;
    if (_source0.is_Fail()) {
      return GoalIr.Option.<__T>create_None(_td___T);
    } else {
      __T _0___mcc_h0 = ((GoalRender.PR_Ok<__T>)_source0)._v;
      dafny.DafnySequence<? extends GoalRender.Tok> _1___mcc_h1 = ((GoalRender.PR_Ok<__T>)_source0)._rest;
      dafny.DafnySequence<? extends GoalRender.Tok> _2_rest = _1___mcc_h1;
      __T _3_v = _0___mcc_h0;
      if ((java.math.BigInteger.valueOf((_2_rest).length())).signum() == 0) {
        return GoalIr.Option.<__T>create_Some(_td___T, _3_v);
      } else {
        return GoalIr.Option.<__T>create_None(_td___T);
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncResPat(GoalIr.ResPat p) {
    GoalIr.ResPat _source0 = p;
    if (_source0.is_PStar()) {
      return dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(630L)));
    } else {
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _0___mcc_h0 = ((GoalIr.ResPat_PSet)_source0)._ids;
      dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _1_ids = _0___mcc_h0;
      return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(631L))), GoalRender.__default.EncStrs(_1_ids));
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncNC(GoalCompile.NC c) {
    GoalCompile.NC _source0 = c;
    if (_source0.is_NTrue()) {
      return dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(600L)));
    } else if (_source0.is_NFalse()) {
      return dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(601L)));
    } else if (_source0.is_NAtom()) {
      GoalIr.Op _0___mcc_h0 = ((GoalCompile.NC_NAtom)_source0)._op;
      GoalIr.Term _1___mcc_h1 = ((GoalCompile.NC_NAtom)_source0)._l;
      GoalIr.Term _2___mcc_h2 = ((GoalCompile.NC_NAtom)_source0)._r;
      GoalIr.Term _3_r = _2___mcc_h2;
      GoalIr.Term _4_l = _1___mcc_h1;
      GoalIr.Op _5_op = _0___mcc_h0;
      return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(602L))), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncOp(_5_op), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncTerm(_4_l), GoalRender.__default.EncTerm(_3_r))));
    } else if (_source0.is_NAnd()) {
      GoalCompile.NC _6___mcc_h3 = ((GoalCompile.NC_NAnd)_source0)._a;
      GoalCompile.NC _7___mcc_h4 = ((GoalCompile.NC_NAnd)_source0)._b;
      GoalCompile.NC _8_y = _7___mcc_h4;
      GoalCompile.NC _9_x = _6___mcc_h3;
      return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(603L))), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncNC(_9_x), __default.EncNC(_8_y)));
    } else {
      GoalCompile.NC _10___mcc_h5 = ((GoalCompile.NC_NOr)_source0)._a;
      GoalCompile.NC _11___mcc_h6 = ((GoalCompile.NC_NOr)_source0)._b;
      GoalCompile.NC _12_y = _11___mcc_h6;
      GoalCompile.NC _13_x = _10___mcc_h5;
      return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(604L))), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncNC(_13_x), __default.EncNC(_12_y)));
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLPred(GoalCompile.LPred p) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(620L))), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncStr((p).dtor_gid()), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncStr((p).dtor_verb()), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncResPat((p).dtor_res()), __default.EncNC((p).dtor_cond())))));
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLProh(GoalCompile.LProh p) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(640L))), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncStr((p).dtor_pid()), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncStrs((p).dtor_verbs()), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncResPat((p).dtor_res()), __default.EncNC((p).dtor_cond())))));
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLCeil(GoalCompile.LCeil c) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(610L))), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncStr((c).dtor_bid()), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncStrs(((c).dtor_sel()).dtor_gids()), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncStrs(((c).dtor_sel()).dtor_verbs()), GoalRender.__default.EncBCore((c).dtor_core())))));
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLPredsElems(dafny.DafnySequence<? extends GoalCompile.LPred> xs) {
    dafny.DafnySequence<? extends GoalRender.Tok> _0___accumulator = dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, __default.EncLPred(((GoalCompile.LPred)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalCompile.LPred> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLPreds(dafny.DafnySequence<? extends GoalCompile.LPred> xs) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncLPredsElems(xs));
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLProhsElems(dafny.DafnySequence<? extends GoalCompile.LProh> xs) {
    dafny.DafnySequence<? extends GoalRender.Tok> _0___accumulator = dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, __default.EncLProh(((GoalCompile.LProh)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalCompile.LProh> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLProhs(dafny.DafnySequence<? extends GoalCompile.LProh> xs) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncLProhsElems(xs));
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLCeilsElems(dafny.DafnySequence<? extends GoalCompile.LCeil> xs) {
    dafny.DafnySequence<? extends GoalRender.Tok> _0___accumulator = dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, __default.EncLCeil(((GoalCompile.LCeil)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalCompile.LCeil> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncLCeils(dafny.DafnySequence<? extends GoalCompile.LCeil> xs) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncLCeilsElems(xs));
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncNCsElems(dafny.DafnySequence<? extends GoalCompile.NC> xs) {
    dafny.DafnySequence<? extends GoalRender.Tok> _0___accumulator = dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor());
    TAIL_CALL_START: while (true) {
      if ((java.math.BigInteger.valueOf((xs).length())).signum() == 0) {
        return dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, dafny.DafnySequence.<GoalRender.Tok> empty(GoalRender.Tok._typeDescriptor()));
      } else {
        _0___accumulator = dafny.DafnySequence.<GoalRender.Tok>concatenate(_0___accumulator, __default.EncNC(((GoalCompile.NC)(java.lang.Object)((xs).select(dafny.Helpers.toInt((java.math.BigInteger.ZERO)))))));
        dafny.DafnySequence<? extends GoalCompile.NC> _in0 = (xs).drop(java.math.BigInteger.ONE);
        xs = _in0;
        continue TAIL_CALL_START;
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncNCs(dafny.DafnySequence<? extends GoalCompile.NC> xs) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.valueOf((xs).length()))), __default.EncNCsElems(xs));
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> EncPol(GoalCompile.Pol p) {
    return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TKw(java.math.BigInteger.valueOf(650L))), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncLPreds((p).dtor_preds()), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncLProhs((p).dtor_prohs()), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncLCeils((p).dtor_ceils()), dafny.DafnySequence.<GoalRender.Tok>concatenate(__default.EncNCs((p).dtor_escs()), dafny.DafnySequence.<GoalRender.Tok>concatenate(GoalRender.__default.EncValidity((p).dtor_validity()), GoalRender.__default.EncDeleg((p).dtor_deleg())))))));
  }
  public static GoalRender.Tok MkKw(java.math.BigInteger k) {
    return GoalRender.Tok.create_TKw(k);
  }
  public static GoalRender.Tok MkI(java.math.BigInteger i) {
    return GoalRender.Tok.create_TI(i);
  }
  public static GoalRender.Tok MkS(dafny.DafnySequence<? extends dafny.CodePoint> s) {
    return GoalRender.Tok.create_TS(s);
  }
  public static java.math.BigInteger TokKind(GoalRender.Tok t) {
    GoalRender.Tok _source0 = t;
    if (_source0.is_TKw()) {
      java.math.BigInteger _0___mcc_h0 = ((GoalRender.Tok_TKw)_source0)._k;
      return java.math.BigInteger.ZERO;
    } else if (_source0.is_TI()) {
      java.math.BigInteger _1___mcc_h1 = ((GoalRender.Tok_TI)_source0)._i;
      return java.math.BigInteger.ONE;
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h2 = ((GoalRender.Tok_TS)_source0)._s;
      return java.math.BigInteger.valueOf(2L);
    }
  }
  public static java.math.BigInteger TokKw(GoalRender.Tok t) {
    GoalRender.Tok _source0 = t;
    if (_source0.is_TKw()) {
      java.math.BigInteger _0___mcc_h0 = ((GoalRender.Tok_TKw)_source0)._k;
      java.math.BigInteger _1_k = _0___mcc_h0;
      return _1_k;
    } else if (_source0.is_TI()) {
      java.math.BigInteger _2___mcc_h2 = ((GoalRender.Tok_TI)_source0)._i;
      return java.math.BigInteger.ZERO;
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _3___mcc_h4 = ((GoalRender.Tok_TS)_source0)._s;
      return java.math.BigInteger.ZERO;
    }
  }
  public static java.math.BigInteger TokInt(GoalRender.Tok t) {
    GoalRender.Tok _source0 = t;
    if (_source0.is_TKw()) {
      java.math.BigInteger _0___mcc_h0 = ((GoalRender.Tok_TKw)_source0)._k;
      return java.math.BigInteger.ZERO;
    } else if (_source0.is_TI()) {
      java.math.BigInteger _1___mcc_h2 = ((GoalRender.Tok_TI)_source0)._i;
      java.math.BigInteger _2_i = _1___mcc_h2;
      return _2_i;
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _3___mcc_h4 = ((GoalRender.Tok_TS)_source0)._s;
      return java.math.BigInteger.ZERO;
    }
  }
  public static dafny.DafnySequence<? extends dafny.CodePoint> TokStr(GoalRender.Tok t) {
    GoalRender.Tok _source0 = t;
    if (_source0.is_TKw()) {
      java.math.BigInteger _0___mcc_h0 = ((GoalRender.Tok_TKw)_source0)._k;
      return dafny.DafnySequence.asUnicodeString("");
    } else if (_source0.is_TI()) {
      java.math.BigInteger _1___mcc_h2 = ((GoalRender.Tok_TI)_source0)._i;
      return dafny.DafnySequence.asUnicodeString("");
    } else {
      dafny.DafnySequence<? extends dafny.CodePoint> _2___mcc_h4 = ((GoalRender.Tok_TS)_source0)._s;
      dafny.DafnySequence<? extends dafny.CodePoint> _3_s = _2___mcc_h4;
      return _3_s;
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> Bad() {
    return dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.valueOf(9L)));
  }
  public static GoalIr.Option<GoalIr.Goal> ParseG(dafny.DafnySequence<? extends GoalRender.Tok> ts) {
    return GoalRender.__default.Parse(ts);
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> TypecheckT(dafny.DafnySequence<? extends GoalRender.Tok> gt, dafny.DafnySequence<? extends GoalRender.Tok> ot)
  {
    dafny.Tuple2<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>> _source0 = dafny.Tuple2.<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>>create(__default.ParseG(gt), __default.<GoalIr.Ontology>Whole(GoalIr.Ontology._typeDescriptor(), __default.DecOntology(ot)));
    GoalIr.Option<GoalIr.Goal> _0___mcc_h0 = ((GoalIr.Option<GoalIr.Goal>)(java.lang.Object)(((dafny.Tuple2<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>>)_source0).dtor__0()));
    GoalIr.Option<GoalIr.Ontology> _1___mcc_h1 = ((GoalIr.Option<GoalIr.Ontology>)(java.lang.Object)(((dafny.Tuple2<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>>)_source0).dtor__1()));
    GoalIr.Option<GoalIr.Goal> _source1 = _0___mcc_h0;
    if (_source1.is_None()) {
      return __default.Bad();
    } else {
      GoalIr.Goal _2___mcc_h4 = ((GoalIr.Option_Some<GoalIr.Goal>)_source1)._v;
      GoalIr.Option<GoalIr.Ontology> _source2 = _1___mcc_h1;
      if (_source2.is_None()) {
        return __default.Bad();
      } else {
        GoalIr.Ontology _3___mcc_h6 = ((GoalIr.Option_Some<GoalIr.Ontology>)_source2)._v;
        GoalIr.Ontology _4_o = _3___mcc_h6;
        GoalIr.Goal _5_g = _2___mcc_h4;
        dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _6_rs = GoalCompile.__default.TypeReasons(_4_o, _5_g);
        if ((java.math.BigInteger.valueOf((_6_rs).length())).signum() == 0) {
          return dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ZERO));
        } else {
          return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ONE)), GoalRender.__default.EncStrs(_6_rs));
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> CompileT(dafny.DafnySequence<? extends GoalRender.Tok> gt, dafny.DafnySequence<? extends GoalRender.Tok> ot)
  {
    dafny.Tuple2<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>> _source0 = dafny.Tuple2.<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>>create(__default.ParseG(gt), __default.<GoalIr.Ontology>Whole(GoalIr.Ontology._typeDescriptor(), __default.DecOntology(ot)));
    GoalIr.Option<GoalIr.Goal> _0___mcc_h0 = ((GoalIr.Option<GoalIr.Goal>)(java.lang.Object)(((dafny.Tuple2<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>>)_source0).dtor__0()));
    GoalIr.Option<GoalIr.Ontology> _1___mcc_h1 = ((GoalIr.Option<GoalIr.Ontology>)(java.lang.Object)(((dafny.Tuple2<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>>)_source0).dtor__1()));
    GoalIr.Option<GoalIr.Goal> _source1 = _0___mcc_h0;
    if (_source1.is_None()) {
      return __default.Bad();
    } else {
      GoalIr.Goal _2___mcc_h4 = ((GoalIr.Option_Some<GoalIr.Goal>)_source1)._v;
      GoalIr.Option<GoalIr.Ontology> _source2 = _1___mcc_h1;
      if (_source2.is_None()) {
        return __default.Bad();
      } else {
        GoalIr.Ontology _3___mcc_h6 = ((GoalIr.Option_Some<GoalIr.Ontology>)_source2)._v;
        GoalIr.Ontology _4_o = _3___mcc_h6;
        GoalIr.Goal _5_g = _2___mcc_h4;
        GoalCompile.CResult _source3 = GoalCompile.__default.Compile(_4_o, _5_g);
        if (_source3.is_Compiled()) {
          GoalCompile.Pol _6___mcc_h8 = ((GoalCompile.CResult_Compiled)_source3)._p;
          GoalCompile.Pol _7_p = _6___mcc_h8;
          return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ZERO)), __default.EncPol(_7_p));
        } else {
          dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _8___mcc_h9 = ((GoalCompile.CResult_CEscalate)_source3)._reasons;
          dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _9_rs = _8___mcc_h9;
          return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ONE)), GoalRender.__default.EncStrs(_9_rs));
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> DecideGoalT(dafny.DafnySequence<? extends GoalRender.Tok> gt, dafny.DafnySequence<? extends GoalRender.Tok> ot, dafny.DafnySequence<? extends GoalRender.Tok> at, dafny.DafnySequence<? extends GoalRender.Tok> ht)
  {
    dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>> _source0 = dafny.Tuple4.<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>create(__default.ParseG(gt), __default.<GoalIr.Ontology>Whole(GoalIr.Ontology._typeDescriptor(), __default.DecOntology(ot)), __default.<GoalIr.Act>Whole(GoalIr.Act._typeDescriptor(), __default.DecAct(at)), __default.<GoalIr.Hist>Whole(GoalIr.Hist._typeDescriptor(), __default.DecHist(ht)));
    GoalIr.Option<GoalIr.Goal> _0___mcc_h0 = ((GoalIr.Option<GoalIr.Goal>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__0()));
    GoalIr.Option<GoalIr.Ontology> _1___mcc_h1 = ((GoalIr.Option<GoalIr.Ontology>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__1()));
    GoalIr.Option<GoalIr.Act> _2___mcc_h2 = ((GoalIr.Option<GoalIr.Act>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__2()));
    GoalIr.Option<GoalIr.Hist> _3___mcc_h3 = ((GoalIr.Option<GoalIr.Hist>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__3()));
    GoalIr.Option<GoalIr.Goal> _source1 = _0___mcc_h0;
    if (_source1.is_None()) {
      return __default.Bad();
    } else {
      GoalIr.Goal _4___mcc_h8 = ((GoalIr.Option_Some<GoalIr.Goal>)_source1)._v;
      GoalIr.Option<GoalIr.Ontology> _source2 = _1___mcc_h1;
      if (_source2.is_None()) {
        return __default.Bad();
      } else {
        GoalIr.Ontology _5___mcc_h10 = ((GoalIr.Option_Some<GoalIr.Ontology>)_source2)._v;
        GoalIr.Option<GoalIr.Act> _source3 = _2___mcc_h2;
        if (_source3.is_None()) {
          return __default.Bad();
        } else {
          GoalIr.Act _6___mcc_h12 = ((GoalIr.Option_Some<GoalIr.Act>)_source3)._v;
          GoalIr.Option<GoalIr.Hist> _source4 = _3___mcc_h3;
          if (_source4.is_None()) {
            return __default.Bad();
          } else {
            GoalIr.Hist _7___mcc_h14 = ((GoalIr.Option_Some<GoalIr.Hist>)_source4)._v;
            GoalIr.Hist _8_h = _7___mcc_h14;
            GoalIr.Act _9_a = _6___mcc_h12;
            GoalIr.Ontology _10_o = _5___mcc_h10;
            GoalIr.Goal _11_g = _4___mcc_h8;
            return dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ZERO), GoalRender.Tok.create_TI(GoalIr.__default.DG(_10_o, _11_g, _9_a, _8_h)));
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> DecidePolicyT(dafny.DafnySequence<? extends GoalRender.Tok> gt, dafny.DafnySequence<? extends GoalRender.Tok> ot, dafny.DafnySequence<? extends GoalRender.Tok> at, dafny.DafnySequence<? extends GoalRender.Tok> ht)
  {
    dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>> _source0 = dafny.Tuple4.<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>create(__default.ParseG(gt), __default.<GoalIr.Ontology>Whole(GoalIr.Ontology._typeDescriptor(), __default.DecOntology(ot)), __default.<GoalIr.Act>Whole(GoalIr.Act._typeDescriptor(), __default.DecAct(at)), __default.<GoalIr.Hist>Whole(GoalIr.Hist._typeDescriptor(), __default.DecHist(ht)));
    GoalIr.Option<GoalIr.Goal> _0___mcc_h0 = ((GoalIr.Option<GoalIr.Goal>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__0()));
    GoalIr.Option<GoalIr.Ontology> _1___mcc_h1 = ((GoalIr.Option<GoalIr.Ontology>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__1()));
    GoalIr.Option<GoalIr.Act> _2___mcc_h2 = ((GoalIr.Option<GoalIr.Act>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__2()));
    GoalIr.Option<GoalIr.Hist> _3___mcc_h3 = ((GoalIr.Option<GoalIr.Hist>)(java.lang.Object)(((dafny.Tuple4<GoalIr.Option<GoalIr.Goal>, GoalIr.Option<GoalIr.Ontology>, GoalIr.Option<GoalIr.Act>, GoalIr.Option<GoalIr.Hist>>)_source0).dtor__3()));
    GoalIr.Option<GoalIr.Goal> _source1 = _0___mcc_h0;
    if (_source1.is_None()) {
      return __default.Bad();
    } else {
      GoalIr.Goal _4___mcc_h8 = ((GoalIr.Option_Some<GoalIr.Goal>)_source1)._v;
      GoalIr.Option<GoalIr.Ontology> _source2 = _1___mcc_h1;
      if (_source2.is_None()) {
        return __default.Bad();
      } else {
        GoalIr.Ontology _5___mcc_h10 = ((GoalIr.Option_Some<GoalIr.Ontology>)_source2)._v;
        GoalIr.Option<GoalIr.Act> _source3 = _2___mcc_h2;
        if (_source3.is_None()) {
          return __default.Bad();
        } else {
          GoalIr.Act _6___mcc_h12 = ((GoalIr.Option_Some<GoalIr.Act>)_source3)._v;
          GoalIr.Option<GoalIr.Hist> _source4 = _3___mcc_h3;
          if (_source4.is_None()) {
            return __default.Bad();
          } else {
            GoalIr.Hist _7___mcc_h14 = ((GoalIr.Option_Some<GoalIr.Hist>)_source4)._v;
            GoalIr.Hist _8_h = _7___mcc_h14;
            GoalIr.Act _9_a = _6___mcc_h12;
            GoalIr.Ontology _10_o = _5___mcc_h10;
            GoalIr.Goal _11_g = _4___mcc_h8;
            GoalCompile.CResult _source5 = GoalCompile.__default.Compile(_10_o, _11_g);
            if (_source5.is_Compiled()) {
              GoalCompile.Pol _12___mcc_h16 = ((GoalCompile.CResult_Compiled)_source5)._p;
              GoalCompile.Pol _13_p = _12___mcc_h16;
              dafny.Tuple2<java.math.BigInteger, GoalWitness.Wit> _14_r = GoalWitness.__default.DecideW(_13_p, _9_a, _8_h);
              return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ZERO), GoalRender.Tok.create_TI((_14_r).dtor__0()), GoalRender.Tok.create_TS(((_14_r).dtor__1()).dtor_gid())), GoalRender.__default.EncStrs(((_14_r).dtor__1()).dtor_bids())), dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI((((java.util.Objects.equals((_14_r).dtor__0(), GoalIr.__default.Allow())) && (GoalWitness.__default.VerifyWitness(_13_p, _9_a, _8_h, (_14_r).dtor__1()))) ? (java.math.BigInteger.ONE) : (java.math.BigInteger.ZERO)))));
            } else {
              dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _15___mcc_h17 = ((GoalCompile.CResult_CEscalate)_source5)._reasons;
              dafny.DafnySequence<? extends dafny.DafnySequence<? extends dafny.CodePoint>> _16_rs = _15___mcc_h17;
              return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ONE)), GoalRender.__default.EncStrs(_16_rs));
            }
          }
        }
      }
    }
  }
  public static dafny.DafnySequence<? extends GoalRender.Tok> RenderT(dafny.DafnySequence<? extends GoalRender.Tok> gt) {
    GoalIr.Option<GoalIr.Goal> _source0 = __default.ParseG(gt);
    if (_source0.is_None()) {
      return __default.Bad();
    } else {
      GoalIr.Goal _0___mcc_h0 = ((GoalIr.Option_Some<GoalIr.Goal>)_source0)._v;
      GoalIr.Goal _1_g = _0___mcc_h0;
      return dafny.DafnySequence.<GoalRender.Tok>concatenate(dafny.DafnySequence.<GoalRender.Tok> of(GoalRender.Tok._typeDescriptor(), GoalRender.Tok.create_TI(java.math.BigInteger.ZERO)), GoalRender.__default.Render(_1_g));
    }
  }
  @Override
  public java.lang.String toString() {
    return "GoalApi._default";
  }
}
