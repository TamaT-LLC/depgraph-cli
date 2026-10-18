use std::{
    alloc::{GlobalAlloc, Layout, System},
    fmt::Write as _,
    fs,
    io::Write as _,
    path::Path,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use depgraph_rust_worker::{HirMode, ScanResult, emit_events, scan_with_options};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static MEASURING: AtomicBool = AtomicBool::new(false);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    if MEASURING.load(Ordering::Relaxed) {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: Every operation delegates to System with the original pointer/layout;
// the counters observe sizes and never access or change allocated memory.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            allocated(size);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Starts a measured interval and returns the live heap it starts from.
fn start_measuring() -> usize {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    base
}

/// Ends a measured interval and returns the peak heap above `base`.
fn stop_measuring(base: usize) -> usize {
    MEASURING.store(false, Ordering::Relaxed);
    PEAK.load(Ordering::Relaxed).saturating_sub(base)
}

fn live_above(base: usize) -> usize {
    LIVE.load(Ordering::Relaxed).saturating_sub(base)
}

const FEW_MODULES: usize = 8;
const MANY_MODULES: usize = 32;
const ELEMENTS_PER_MODULE: usize = 6_000;
const LINKS: usize = 2_000;

/// Each heavy module is one function with a large flat array literal: parsing
/// it builds a big syntax tree, yet it declares no dependency site. The links
/// module supplies the graph: imports, calls, and items that become nodes,
/// dependency sites, and edges, identical whatever the heavy module count.
fn write_fixture(root: &Path, modules: usize) {
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"heavy-syntax\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    )
    .unwrap();
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    let mut lib = String::from("pub mod links;\n");
    for module in 0..modules {
        writeln!(lib, "pub mod m{module:02};").unwrap();
        let mut body = format!("pub fn values_{module:02}() -> usize {{\n    let values = [\n");
        for element in 0..ELEMENTS_PER_MODULE {
            write!(body, "{element}u64, ").unwrap();
            if element % 64 == 63 {
                body.push('\n');
            }
        }
        body.push_str("\n    ];\n    values.len()\n}\n");
        fs::write(src.join(format!("m{module:02}.rs")), body).unwrap();
    }
    let mut links = String::new();
    for item in 0..LINKS {
        writeln!(
            links,
            "use crate::m00::values_00 as v{item};\npub struct Link{item};\npub fn link_{item}() -> usize {{ v{item}() + crate::m00::values_00() }}",
        )
        .unwrap();
    }
    fs::write(src.join("links.rs"), links).unwrap();
    fs::write(src.join("lib.rs"), lib).unwrap();
}

/// Scans a fixture with `modules` heavy modules and returns the result with
/// the peak heap above the start of the scan.
fn measured_scan(modules: usize) -> (ScanResult, usize) {
    let temp = tempfile::tempdir().unwrap();
    write_fixture(temp.path(), modules);
    let base = start_measuring();
    let result = scan_with_options(temp.path(), None, HirMode::SyntaxOnly).unwrap();
    let peak = stop_measuring(base);
    let parsed_modules = result
        .files
        .iter()
        .filter(|file| file.path.ends_with(".rs") && !file.skipped)
        .count();
    assert_eq!(
        parsed_modules,
        modules + 2,
        "every fixture module must parse"
    );
    (result, peak)
}

// This integration binary has one test, so no other test thread allocates
// inside the measured intervals. Measuring the live Rust heap rather than RSS
// keeps the result independent of how the platform allocator retains pages.
#[test]
fn syntax_only_scan_and_event_output_do_not_accumulate_whole_scan_copies() {
    // T: the heap one heavy module's syntax tree occupies while it is alive.
    let temp = tempfile::tempdir().unwrap();
    write_fixture(temp.path(), 1);
    let one_module = fs::read_to_string(temp.path().join("src/m00.rs")).unwrap();
    let before_parse = LIVE.load(Ordering::Relaxed);
    let tree = syn::parse_file(&one_module).unwrap();
    let tree_bytes = live_above(before_parse);
    drop(tree);
    drop(one_module);

    // The graph is the same for both fixtures, so the peak difference is what
    // the extra heavy modules cost. Keeping every tree to the end of the scan
    // makes it about (MANY - FEW) * T; dropping each tree once its occurrences
    // are collected leaves only the source text and occurrences per module.
    let (few_result, few_peak) = measured_scan(FEW_MODULES);
    drop(few_result);
    let (many_result, many_peak) = measured_scan(MANY_MODULES);
    let extra_module_peak = many_peak.saturating_sub(few_peak);

    // L: the live scan result. Cloning it into an event vector holds a second
    // copy (plus validator copies in debug builds); streaming the owned result
    // moves each record into its event and frees it once written.
    let result_base = LIVE.load(Ordering::Relaxed);
    drop(many_result);
    let result_bytes = result_base.saturating_sub(LIVE.load(Ordering::Relaxed));
    let (many_result, _) = measured_scan(MANY_MODULES);
    let emit_base = start_measuring();
    let mut output = std::io::sink();
    let events = emit_events("syntax-only-memory", many_result, |event| {
        serde_json::to_writer(&mut output, &event)?;
        output.write_all(b"\n")?;
        Ok(())
    })
    .unwrap();
    let emit_peak = stop_measuring(emit_base);

    eprintln!(
        "T={tree_bytes} few peak={few_peak} many peak={many_peak} L={result_bytes} emit peak={emit_peak} events={events}"
    );
    assert!(
        extra_module_peak < 4 * tree_bytes,
        "{} extra heavy modules raised the syntax-only scan peak by {extra_module_peak} B; it must stay below 4 trees ({tree_bytes} B each)",
        MANY_MODULES - FEW_MODULES
    );
    assert!(
        emit_peak < result_bytes / 4,
        "event output peak {emit_peak} B must stay below a quarter of the scan result {result_bytes} B"
    );
}
