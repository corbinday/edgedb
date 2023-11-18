
from ..data import data_ops as e
from ..data import expr_ops as eops
from ..data import type_ops as tops
from ..data import path_factor as pops
from typing import List, Tuple, Dict


def get_key_dependency(tp : e.DefaultTp) -> List[str]:
    new_head_name = eops.next_name("head_name_test")
    instantiaed = eops.instantiate_expr(e.FreeVarExpr(new_head_name), tp.expr)
    paths = pops.get_all_paths(instantiaed)
    deps = []
    for p in paths:
        if eops.get_path_head(p) == new_head_name:
            first_path_comp = eops.get_first_path_component(p)
            match first_path_comp:
                case e.FreeVarExpr(_):
                    raise ValueError("Path head is FreeVar, cannot do insert")
                case e.ObjectProjExpr(subject=_, label=lbl):
                    deps.append(lbl)
                case e.LinkPropProjExpr(_, _):
                    raise ValueError("default expr should not do link prop proj")
                case e.BackLinkExpr(_) | e.TpIntersectExpr(_):
                    continue # this is fine
    return deps
                
def type_elaborate_default_tp(ctx: e.TcCtx, default_expr: e.Expr) -> e.Expr:
    from .typechecking import synthesize_type, check_type
    elabed =  synthesize_type(ctx, default_expr)[1]
    return elabed

def insert_proprerty_checking(ctx: e.TcCtx, attr_expr : e.Expr, attr_tp : e.ResultTp) -> e.Expr:
    # for breaking circular dependency
    from .typechecking import synthesize_type, check_type
    target_tp = attr_tp.tp
    target_mode = attr_tp.mode
    if tops.tp_is_primitive(target_tp):
        return check_type(ctx, attr_expr, attr_tp)
    else:
        match target_tp:
            case e.DefaultTp(expr=_, tp=tp): 
                # since we're inserting an actual value, default is overridden
                return insert_proprerty_checking(ctx, attr_expr, e.ResultTp(tp, target_mode))
            case e.NamedNominalLinkTp(name=target_name, linkprop=lp):
                (synthesized_tp, expr_ck) = synthesize_type(ctx, attr_expr)
                tops.assert_cardinal_subtype(synthesized_tp.mode, target_mode)
                ck_lp = lp.val

                # get the synthesized link props
                match synthesized_tp.tp:
                    case e.NamedNominalLinkTp(name=synth_name, linkprop=lp2):
                        if target_name != synth_name:
                            raise ValueError("Unmatched target and synth name", target_name, synth_name)
                        synth_lp = lp2.val
                    case e.NominalLinkTp(subject=_, name=synth_name, linkprop=lp2):
                        if target_name != synth_name:
                            raise ValueError("Unmatched target and synth name", target_name, synth_name)
                        synth_lp = lp2.val
                    case _:
                        raise ValueError("Unrecognized synthesized type", synthesized_tp)
                
                # we do not support heterogenous link targets
                for k in synth_lp.keys():
                    this_tp = ck_lp[k].tp
                    if k not in ck_lp.keys():
                        raise ValueError("Link prop not in type", k, ck_lp.keys())
                    elif isinstance(synth_lp[k].tp, e.ComputableTp):
                        raise ValueError("Cannot define computable tp")
                    elif isinstance(this_tp, e.DefaultTp):
                        tops.assert_real_subtype(ctx, synth_lp[k].tp, this_tp.tp)
                    else:
                        tops.assert_real_subtype(ctx, synth_lp[k].tp, ck_lp[k].tp)

                additional_lps : Dict[str, e.Expr] = {}

                for k in ck_lp.keys():
                    this_tp = ck_lp[k].tp
                    if k in synth_lp.keys():
                        continue
                    elif isinstance(ck_lp[k].tp, e.ComputableTp):
                        continue
                    elif isinstance(this_tp, e.DefaultTp):
                        default_expr = this_tp.expr
                        if eops.binding_is_unnamed(default_expr):
                            additional_lps[k] = type_elaborate_default_tp(
                                ctx, eops.instantiate_expr(e.FreeVarExpr("LP_DEFAULT_SHOULD_NOT_OCCUR"), default_expr))
                        else:
                            raise ValueError("Default Tp is not unnamed", this_tp.expr)
                    elif tops.mode_is_optional(ck_lp[k].mode):
                        additional_lps[k] = e.MultiSetExpr(expr=[])
                    else:
                        raise ValueError("Missing link prop", k, "synthesized keys", synth_lp.keys(), "required keys", ck_lp.keys())
                        
                if len(additional_lps.keys()) == 0:
                    return expr_ck
                else:
                    return e.ShapedExprExpr(expr_ck, 
                        e.ShapeExpr(
                            shape={
                                e.LinkPropLabel(k): eops.abstract_over_expr(v)
                                for (k,v) in additional_lps.items()
                            }
                        ))
            case _:
                raise ValueError("Unrecognized Attribute Target Type", target_tp)
        


def insert_checking(ctx: e.TcCtx, expr: e.InsertExpr) -> e.Expr:
    # for breaking circular dependency
    from .typechecking import synthesize_type, check_type

    schema_tp = ctx.schema.val[expr.name]
    new_v: Dict[str, e.Expr] = {}
    for (k, v) in expr.new.items():
        if k not in schema_tp.val:
            raise ValueError(f"Key {k} not in schema for {expr.name}")
        target_tp = schema_tp.val[k]
        if isinstance(target_tp, e.ComputableTp):
            raise ValueError(f"Key {k} is computable in {expr.name}, modification of computable types prohibited")
        vv = insert_proprerty_checking(ctx, v, schema_tp.val[k])
        new_v = {**new_v, k: vv}

    # add optional fields that do not have a default
    for (k, target_tp) in schema_tp.val.items():
        if (tops.mode_is_optional(target_tp.mode)
            and not isinstance(target_tp.tp, e.DefaultTp)
            and not isinstance(target_tp.tp, e.ComputableTp)
            and k not in new_v):
            new_v = {**new_v, k: e.MultiSetExpr(expr=[])}

    # check non-optional fields
    missing_keys = []
    for (k, target_tp) in schema_tp.val.items():
        if isinstance(target_tp.tp, e.ComputableTp):
            continue
        if isinstance(target_tp.tp, e.DefaultTp):
            continue
        if k not in new_v:
            missing_keys.append(k)
    if len(missing_keys) > 0:
        raise ValueError(f"Missing keys {missing_keys} in insert for {expr.name}")

    
    dependent_keys : Dict[str, str] = {} # a list of keys that are dependent, need to extract them in this order, second element provides the binder name
    def add_deps_from_new_v(deps: List[str]) -> None:
        for k in deps:
            if k in new_v and k not in dependent_keys:
                dependent_keys[k] = eops.next_name(f"insert_{expr.name}_{k}")
    def get_shaped_from_deps(deps: List[str]) -> e.ShapedExprExpr:
        return e.ShapedExprExpr(
                expr=e.FreeObjectExpr(),
                shape=e.ShapeExpr(
                    shape={e.StrLabel(k): eops.abstract_over_expr(e.FreeVarExpr(dependent_keys[k])) for k in deps}
                ))

    pending_default: Dict[str, List[str]] = {} # key and its dependent keys
    # topologically sort the default insertions.
    for (k, target_tp) in schema_tp.val.items():
        if isinstance(target_tp, e.DefaultTp):
            deps = get_key_dependency(target_tp)
            if len(deps) == 0:
                actual_v = eops.instantiate_expr(target_tp.expr, e.FreeVarExpr("INSERT_SHOULD_NOT_OCCUR"))
                new_v = {**new_v, k: type_elaborate_default_tp(actual_v)}
            else:
                # add to dependent_keys those in new_v
                add_deps_from_new_v(deps)
                # if all dependencies are currently in add new_v
                if all(k in dependent_keys.keys() for k in deps):
                    actual_v = e.WithExpr(
                        get_shaped_from_deps(deps),
                        target_tp.expr)
                    new_v = {**new_v, k: actual_v} #TODO THIS NEEDS ELABORATION
                else:
                    assert k not in pending_default, "only iterating over schema once, no duplicate keys"
                    pending_default[k] = deps

    # process pending keys until all are resolved
    while len(pending_default) > 0:
        # find a key that has all dependencies resolved
        for (k, deps) in pending_default.items():
            add_deps_from_new_v(deps)
            if all(k in dependent_keys.keys() for k in deps):
                target_tp = schema_tp.val[k]
                assert isinstance(target_tp, e.DefaultTp)
                actual_v = e.WithExpr(
                    get_shaped_from_deps(deps),
                    target_tp.expr)
                new_v = {**new_v, k: actual_v} #TODO THIS NEEDS ELABORATION, we need to get the type and add it in the context then perform elaboration
                del pending_default[k]
                break
        else:
            raise ValueError(f"Cannot resolve default value for because of circular dependencies: {pending_default}")


    # now abstract over the dependent keys in order
    result_expr : e.Expr = e.InsertExpr(
        name=expr.name,
        new={k: v  
             for (k, v) in new_v.items()
             if k not in dependent_keys})
    for (k, binder_name) in reversed(dependent_keys.items()):
        result_expr = e.WithExpr(
            new_v[k], 
            eops.abstract_over_expr(result_expr, binder_name)
        )

    # if we are recursing, second time there will not be any dependent keys
    if dependent_keys:
        # This is a hack because we did not enforce the default expression's types. So we recheck everything at the end.
        # TODO: we should optimize checking
        result_expr = synthesize_type(ctx, result_expr)[1]
    return result_expr


def update_checking(ctx: e.TcCtx, update_shape: e.ShapeExpr, subject_tp: e.Tp) -> e.ShapeExpr:
    # for breaking circular dependency
    from . import typechecking as tc
    assert isinstance(subject_tp, e.NamedNominalLinkTp) or isinstance(subject_tp, e.NominalLinkTp), "Expecting link type"
    tp_name = subject_tp.name
    full_tp = ctx.schema.val[tp_name]
    assert all(isinstance(k, e.StrLabel) for k in update_shape.shape.keys()), "Expecting string labels"
    cut_tp = {k : v for (k,v) in full_tp.val.items() 
              if e.StrLabel(k) in update_shape.shape.keys()}
    shape_ck : Dict[e.Label, e.BindingExpr] = {}
    for (k, v) in cut_tp.items():
        ctx_new, shape_body, bnd_var = eops.tcctx_add_binding(
            ctx, update_shape.shape[e.StrLabel(k)], 
            e.ResultTp(subject_tp, e.CardOne))
        shape_body_ck = insert_proprerty_checking(ctx_new, shape_body, v)
        shape_ck[e.StrLabel(k)] = eops.abstract_over_expr(shape_body_ck, bnd_var)

    return e.ShapeExpr(shape=shape_ck)