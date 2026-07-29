//! Reviewed `rustc_private` boundary for compiler-selected mono items.
//!
//! The pinned compiler does not expose its mono-item collector through
//! `rustc_public`. This module is therefore deliberately small: it invokes that
//! single query, classifies the private `InstanceKind`/`ShimKind`, converts each
//! item to its `rustc_public` counterpart, and returns no compiler-internal ID,
//! type, context, or reference.

use std::collections::HashSet;

use rustc_middle::{
    mono::MonoItem as InternalMonoItem,
    ty::{InstanceKind as InternalInstanceKind, ShimKind as InternalShimKind, tls},
};
use rustc_public::mir::mono::{Instance, MonoItem, StaticDef};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewedInstanceKind {
    Item,
    Intrinsic,
    LlvmIntrinsic,
    Virtual { vtable_index: usize },
    Shim(ReviewedShimKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewedShimKind {
    Vtable,
    Reify,
    FnPtr,
    ClosureOnce,
    CoroutineClosure,
    ThreadLocal,
    FutureDropPoll,
    DropGlue,
    Clone,
    FnPtrAddr,
    AsyncDropGlueCtor,
    AsyncDropGlue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewedMonoItem {
    Function {
        instance: Instance,
        kind: ReviewedInstanceKind,
    },
    Static(StaticDef),
}

/// Collect the compiler-selected mono items through the sole private query.
///
/// Global assembly is intentionally rejected by the caller: it has no typed
/// call-graph representation in this contract. Keeping it explicit prevents a
/// future compiler change from being silently treated as source evidence.
pub fn collect_mono_items() -> (Vec<ReviewedMonoItem>, usize) {
    tls::with(|tcx| {
        let items = tcx
            .collect_and_partition_mono_items(())
            .codegen_units
            .iter()
            .flat_map(|unit| unit.items().keys().copied())
            .collect::<HashSet<InternalMonoItem<'_>>>();
        let mut reviewed = Vec::with_capacity(items.len());
        let mut global_asm_count = 0;
        for item in items {
            let reviewed_kind = match item {
                InternalMonoItem::Fn(instance) => Some(classify_instance(instance.def)),
                InternalMonoItem::Static(_) => None,
                InternalMonoItem::GlobalAsm(_) => {
                    global_asm_count += 1;
                    continue;
                }
            };
            match rustc_public::rustc_internal::stable(item) {
                MonoItem::Fn(instance) => reviewed.push(ReviewedMonoItem::Function {
                    instance,
                    kind: reviewed_kind
                        .expect("function mono items always have an instance classification"),
                }),
                MonoItem::Static(definition) => {
                    reviewed.push(ReviewedMonoItem::Static(definition));
                }
                MonoItem::GlobalAsm(_) => {
                    unreachable!("global assembly is counted before stable conversion")
                }
            }
        }
        (reviewed, global_asm_count)
    })
}

fn classify_instance(kind: InternalInstanceKind<'_>) -> ReviewedInstanceKind {
    match kind {
        InternalInstanceKind::Item(_) => ReviewedInstanceKind::Item,
        InternalInstanceKind::Intrinsic(_) => ReviewedInstanceKind::Intrinsic,
        InternalInstanceKind::LlvmIntrinsic(_) => ReviewedInstanceKind::LlvmIntrinsic,
        InternalInstanceKind::Virtual(_, vtable_index) => {
            ReviewedInstanceKind::Virtual { vtable_index }
        }
        InternalInstanceKind::Shim(kind) => ReviewedInstanceKind::Shim(match kind {
            InternalShimKind::VTable(_) => ReviewedShimKind::Vtable,
            InternalShimKind::Reify(_, _) => ReviewedShimKind::Reify,
            InternalShimKind::FnPtr(_, _) => ReviewedShimKind::FnPtr,
            InternalShimKind::ClosureOnce { .. } => ReviewedShimKind::ClosureOnce,
            InternalShimKind::ConstructCoroutineInClosure { .. } => {
                ReviewedShimKind::CoroutineClosure
            }
            InternalShimKind::ThreadLocal(_) => ReviewedShimKind::ThreadLocal,
            InternalShimKind::FutureDropPoll(_, _, _) => ReviewedShimKind::FutureDropPoll,
            InternalShimKind::DropGlue(_, _) => ReviewedShimKind::DropGlue,
            InternalShimKind::Clone(_, _) => ReviewedShimKind::Clone,
            InternalShimKind::FnPtrAddr(_, _) => ReviewedShimKind::FnPtrAddr,
            InternalShimKind::AsyncDropGlueCtor(_, _) => ReviewedShimKind::AsyncDropGlueCtor,
            InternalShimKind::AsyncDropGlue(_, _) => ReviewedShimKind::AsyncDropGlue,
        }),
    }
}
