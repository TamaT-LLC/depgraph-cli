package worker

import (
	"fmt"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const goVTACallGraphEngine = "golang.org/x/tools/go/callgraph/vta@v0.48.0"

type goSSACallKey struct {
	input       *goSSAInput
	callerTypes *types.Package
	position    token.Pos
}

type goSSAGraphIndex struct {
	sites   map[goSSACallKey]bool
	targets map[goSSACallKey]map[*ssa.Function]bool
}

type goSSABuild struct {
	program  *ssa.Program
	initial  []*ssa.Package
	complete bool
	reason   string
}

type goSSAOutcome struct {
	requestedVTA       bool
	pendingSites       int
	vtaSelections      int
	fallbackSelections int
	algorithms         map[string]bool
	fallbackReasons    map[string]bool
}

func (e *goSemanticExtractor) emitSSACalls() {
	e.recordSSAPolicy()
	outcome := &goSSAOutcome{
		requestedVTA: e.state.profile.Properties["go_call_graph_requested"] == "vta",
		pendingSites: len(e.pendingCalls), algorithms: map[string]bool{}, fallbackReasons: map[string]bool{},
	}
	defer e.recordSSAOutcome(outcome)
	e.emitCallGraphLimitDiagnostics()
	if len(e.pendingCalls) == 0 {
		return
	}

	inputs := make([]*goSSAInput, 0)
	seenInputs := map[*goSSAInput]bool{}
	for _, pending := range e.pendingCalls {
		input := pending.context.typed.SSAInput
		if input == nil || seenInputs[input] {
			continue
		}
		seenInputs[input] = true
		inputs = append(inputs, input)
	}
	sort.Slice(inputs, func(left, right int) bool {
		if inputs[left].ModuleRelativeDir != inputs[right].ModuleRelativeDir {
			return inputs[left].ModuleRelativeDir < inputs[right].ModuleRelativeDir
		}
		return inputs[left].ModulePath < inputs[right].ModulePath
	})

	chaByInput := map[*goSSAInput]goSSAGraphIndex{}
	rtaByInput := map[*goSSAInput]goSSAGraphIndex{}
	vtaByInput := map[*goSSAInput]goSSAGraphIndex{}
	vtaFallbackByInput := map[*goSSAInput]string{}
	completeByInput := map[*goSSAInput]bool{}
	buildFailures := map[*goSSAInput]bool{}
	for _, input := range inputs {
		build, err := buildGoSSA(input)
		if err != nil {
			buildFailures[input] = true
			if outcome.requestedVTA {
				outcome.fallbackReasons["ssa_build_failed_unresolved"] = true
			}
			e.complete = false
			e.addSSABuildDiagnostic(input, err)
			continue
		}
		completeByInput[input] = build.complete
		if !build.complete {
			e.complete = false
			e.addSSAPartialDiagnostic(input, build.reason, outcome.requestedVTA)
			if outcome.requestedVTA {
				vtaFallbackByInput[input] = "vta_incomplete_program_fallback"
				outcome.fallbackReasons[vtaFallbackByInput[input]] = true
			}
		}

		chaGraph, err := buildGoCHAGraph(build.program)
		if err != nil {
			buildFailures[input] = true
			e.complete = false
			e.addSSABuildDiagnostic(input, fmt.Errorf("CHA construction failed: %w", err))
			continue
		}
		chaByInput[input] = indexGoSSAGraph(input, chaGraph)

		if outcome.requestedVTA && build.complete {
			vtaGraph, vtaErr := buildGoVTAGraph(build.program)
			if vtaErr != nil {
				vtaFallbackByInput[input] = "vta_construction_failed_fallback"
				outcome.fallbackReasons[vtaFallbackByInput[input]] = true
				e.addSSAVTAFallbackDiagnostic(input, vtaErr)
			} else {
				vtaByInput[input] = indexGoSSAGraph(input, vtaGraph)
			}
		}

		rtaIndex := newGoSSAGraphIndex()
		if build.complete {
			mains := goSSAMainPackages(build.initial)
			for _, mainPackage := range mains {
				roots := goSSAMainRoots(mainPackage)
				if len(roots) == 0 {
					continue
				}
				rtaGraph, rtaErr := buildGoRTAGraph(roots)
				if rtaErr != nil {
					buildFailures[input] = true
					e.complete = false
					e.addSSABuildDiagnostic(input, fmt.Errorf("RTA construction failed: %w", rtaErr))
					break
				}
				mergeGoSSAGraphIndex(&rtaIndex, indexGoSSAGraph(input, rtaGraph))
			}
		}
		if !buildFailures[input] {
			rtaByInput[input] = rtaIndex
		}
	}

	for _, pending := range e.pendingCalls {
		input := pending.context.typed.SSAInput
		if input == nil || buildFailures[input] {
			e.emitPendingUnresolved(pending)
			continue
		}
		key := goSSACallKey{input: input, callerTypes: pending.context.typed.Types, position: pending.call.Lparen}
		algorithm, selectionReason, fallbackReason, index := e.selectGoSSAIndex(
			pending, key, completeByInput[input], chaByInput[input], rtaByInput[input],
			outcome.requestedVTA, vtaByInput[input], vtaFallbackByInput[input],
		)
		outcome.algorithms[algorithm] = true
		if algorithm == "vta" {
			outcome.vtaSelections++
		}
		if fallbackReason != "none" && fallbackReason != "not_requested" {
			outcome.fallbackSelections++
			outcome.fallbackReasons[fallbackReason] = true
		}
		functions := index.targets[key]
		if len(functions) == 0 {
			e.emitPendingUnresolved(pending)
			continue
		}

		targetSet := map[string]bool{}
		unmappable := make([]string, 0)
		for function := range functions {
			nodeIDs, ok, relevant := e.mapGoSSAFunction(pending, function, index, map[*ssa.Function]bool{})
			if !relevant {
				continue
			}
			if !ok || len(nodeIDs) == 0 {
				unmappable = append(unmappable, function.String())
				continue
			}
			for _, nodeID := range nodeIDs {
				targetSet[nodeID] = true
			}
		}
		if len(unmappable) > 0 || len(targetSet) == 0 {
			if len(unmappable) > 0 {
				examples, count, truncated := goSSAUnmappableExamples(unmappable, 20)
				message := fmt.Sprintf(
					"SSA %s has %d candidate(s) that cannot be represented as repository symbols: %s",
					algorithm, count, strings.Join(examples, ", "),
				)
				if truncated {
					message += fmt.Sprintf(" (and %d more)", count-len(examples))
				}
				e.addSSASiteDiagnostic(
					pending,
					"go_ssa_candidate_incomplete",
					message,
					map[string]any{
						"algorithm": algorithm, "reason": "unmappable_candidate",
						"unmappable_count": count, "examples": examples, "truncated": truncated,
					},
				)
			}
			e.emitPendingUnresolved(pending)
			continue
		}
		targetIDs := make([]string, 0, len(targetSet))
		for targetID := range targetSet {
			targetIDs = append(targetIDs, targetID)
		}
		sort.Strings(targetIDs)
		evidence := goSSACandidateEvidence(
			pending, algorithm, selectionReason, fallbackReason, len(targetIDs), outcome.requestedVTA,
		)
		if !e.addCandidateCall(pending, targetIDs, evidence) {
			siteID := goSSAPendingSiteID(e.state.profile.ID, pending, evidence)
			if _, exists := e.state.sites[siteID]; !exists {
				e.addSSASiteDiagnostic(
					pending,
					"go_ssa_candidate_emit_failed",
					"SSA candidates could not be emitted under the semantic call-site contract",
					map[string]any{"algorithm": algorithm, "reason": "candidate_emit_failed"},
				)
				e.emitPendingUnresolved(pending)
			}
		}
	}

	// The packages.Package graph is only needed while this pass runs. Dropping
	// the roots here keeps a completed scan from retaining the full dependency
	// syntax graph through its Result.
	for _, input := range inputs {
		input.Roots = nil
	}
}

func goSSAPendingSiteID(profileID string, pending goSemanticPendingCall, evidence []Evidence) string {
	if pending.callerID == "" || len(evidence) == 0 {
		return ""
	}
	primary := evidence[0]
	return stableIDFromValue("site", map[string]any{
		"condition": canonicalCondition(pending.condition), "kind": "call", "path": primary.Path,
		"profile_id": profileID, "source": pending.callerID, "span": goSemanticSpan(primary),
	})
}

func goSSAUnmappableExamples(values []string, limit int) ([]string, int, bool) {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = true
		}
	}
	ordered := make([]string, 0, len(set))
	for value := range set {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	count := len(ordered)
	if limit < 0 {
		limit = 0
	}
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	return ordered, count, count > len(ordered)
}

func (e *goSemanticExtractor) recordSSAPolicy() {
	if e.state.profile.Properties == nil {
		e.state.profile.Properties = map[string]string{}
	}
	if e.state.profile.Properties["go_call_graph_requested"] == "" {
		e.state.profile.Properties["go_call_graph_requested"] = "rta-cha"
	}
	e.state.profile.Properties["go_ssa_builder_mode"] = "instantiate-generics,serial"
	e.state.profile.Properties["go_call_graph_main_test"] = "rta"
	e.state.profile.Properties["go_call_graph_library_partial"] = "cha"
	e.state.profile.Properties["go_call_graph_vta_prerequisites"] = "complete-program,instantiate-generics,serial-ssa"
	e.state.profile.Properties["go_call_graph_vta_engine"] = goVTACallGraphEngine
}

func (e *goSemanticExtractor) recordSSAOutcome(outcome *goSSAOutcome) {
	if outcome == nil {
		return
	}
	algorithms := make([]string, 0, len(outcome.algorithms))
	for algorithm := range outcome.algorithms {
		algorithms = append(algorithms, algorithm)
	}
	sort.Strings(algorithms)
	reasons := make([]string, 0, len(outcome.fallbackReasons))
	for reason := range outcome.fallbackReasons {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	e.state.profile.Properties["go_call_graph_effective_algorithms"] = strings.Join(algorithms, ",")
	if !outcome.requestedVTA {
		e.state.profile.Properties["go_call_graph_vta_status"] = "not-requested"
		return
	}
	status := "fallback"
	switch {
	case outcome.pendingSites == 0:
		status = "not-applicable"
	case outcome.vtaSelections > 0 && len(reasons) == 0:
		status = "applied"
	case outcome.vtaSelections > 0:
		status = "partial"
	}
	e.state.profile.Properties["go_call_graph_vta_status"] = status
	e.state.profile.Properties["go_call_graph_vta_site_count"] = strconv.Itoa(outcome.vtaSelections)
	e.state.profile.Properties["go_call_graph_vta_fallback_site_count"] = strconv.Itoa(outcome.fallbackSelections)
	e.state.profile.Properties["go_call_graph_vta_fallback_reasons"] = strings.Join(reasons, ",")
}

func (e *goSemanticExtractor) emitCallGraphLimitDiagnostics() {
	paths := make([]string, 0, len(e.sources))
	for path := range e.sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		source := e.sources[path]
		if source == nil || source.AST == nil || source.FileSet == nil {
			continue
		}
		for _, importSpec := range source.AST.Imports {
			importPath, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				continue
			}
			var category, message string
			switch importPath {
			case "unsafe":
				category = "unsafe"
				message = "unsafe operations can cross the statically modeled Go call graph boundary"
			case "plugin":
				category = "plugin"
				message = "plugin loading and symbol lookup cannot be resolved by the closed-world Go call graph"
			case "C":
				category = "native_callback"
				message = "cgo and native callbacks are outside the Go SSA call graph"
			}
			if category != "" {
				e.addCallGraphLimitDiagnostic(
					source.RelPath,
					category,
					message,
					goCallGraphLimitEvidence(source, importSpec.Pos(), importSpec.End(), importPath, category),
				)
			}
		}
		for _, group := range source.AST.Comments {
			for _, comment := range group.List {
				text := strings.TrimSpace(comment.Text)
				category, message := "", ""
				switch {
				case strings.HasPrefix(text, "//go:linkname"):
					category = "go_linkname"
					message = "go:linkname can introduce call targets that are not represented by typed source"
				case strings.HasPrefix(text, "//export "):
					category = "native_callback"
					message = "exported cgo callbacks are outside the Go SSA call graph"
				}
				if category != "" {
					e.addCallGraphLimitDiagnostic(
						source.RelPath,
						category,
						message,
						goCallGraphLimitEvidence(source, comment.Pos(), comment.End(), text, category),
					)
				}
			}
		}
	}

	_ = filepath.WalkDir(e.state.root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() {
			if path != e.state.root && shouldSkipDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(strings.ToLower(entry.Name()), ".s") ||
			strings.HasPrefix(entry.Name(), ".") || strings.HasPrefix(entry.Name(), "_") {
			return nil
		}
		relative := relativePath(e.state.root, path)
		e.addCallGraphLimitDiagnostic(
			relative,
			"assembly",
			"assembly functions and native callbacks are outside the Go SSA call graph",
			nil,
		)
		return nil
	})
}

func goCallGraphLimitEvidence(source *sourceFile, startPos, endPos token.Pos, detail, category string) []Evidence {
	if source == nil || source.FileSet == nil {
		return nil
	}
	start := source.FileSet.PositionFor(startPos, false)
	end := source.FileSet.PositionFor(endPos, false)
	evidence := sourceEvidence(source.RelPath, start.Line, start.Column, end.Line, end.Column, detail)
	if len(evidence) > 0 {
		evidence[0].Properties = map[string]any{"boundary": category}
	}
	return evidence
}

func (e *goSemanticExtractor) addCallGraphLimitDiagnostic(path, category, message string, evidence []Evidence) {
	identity := map[string]any{
		"code": "go_callgraph_limit", "path": path, "profile_id": e.state.profile.ID, "boundary": category,
	}
	diagnostic := Diagnostic{
		Code: "go_callgraph_limit", Severity: "warning", Message: message,
		ProfileID: e.state.profile.ID, Path: path,
		Properties: map[string]any{"boundary": category}, Recoverable: true,
	}
	if len(evidence) > 0 {
		primary := evidence[0]
		identity["span"] = goSemanticSpan(primary)
		diagnostic.StartLine = primary.StartLine
		diagnostic.StartColumn = primary.StartColumn
		diagnostic.EndLine = primary.EndLine
		diagnostic.EndColumn = primary.EndColumn
		diagnostic.Evidence = append([]Evidence(nil), evidence...)
	}
	diagnostic.ID = stableIDFromValue("diagnostic", identity)
	if e.diagnosticIDs[diagnostic.ID] {
		return
	}
	e.diagnosticIDs[diagnostic.ID] = true
	e.state.diagnostics = append(e.state.diagnostics, diagnostic)
}

func buildGoSSA(input *goSSAInput) (build goSSABuild, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("SSA build panicked: %v", recovered)
			build = goSSABuild{}
		}
	}()
	if input == nil || len(input.Roots) == 0 {
		return goSSABuild{}, fmt.Errorf("SSA input has no packages")
	}
	initialPackages := make([]*packages.Package, 0, len(input.Roots))
	for _, root := range input.Roots {
		if root != nil {
			initialPackages = append(initialPackages, root)
		}
	}
	if len(initialPackages) == 0 {
		return goSSABuild{}, fmt.Errorf("SSA input has no non-nil packages")
	}
	complete, reason := goSSAInputCompleteness(initialPackages)
	mode := ssa.InstantiateGenerics | ssa.BuildSerially
	var program *ssa.Program
	var initial []*ssa.Package
	if complete {
		program, initial = ssautil.AllPackages(initialPackages, mode)
	} else {
		program, initial = ssautil.Packages(initialPackages, mode)
	}
	if program == nil {
		return goSSABuild{}, fmt.Errorf("SSA program is unavailable")
	}
	program.Build()
	return goSSABuild{program: program, initial: initial, complete: complete, reason: reason}, nil
}

func goSSAInputCompleteness(roots []*packages.Package) (bool, string) {
	queue := append([]*packages.Package(nil), roots...)
	seen := map[*packages.Package]bool{}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if pkg == nil {
			return false, "the package graph contains a nil package"
		}
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		label := pkg.ID
		if label == "" {
			label = pkg.PkgPath
		}
		switch {
		case len(pkg.Errors) > 0:
			return false, fmt.Sprintf("package %q reports load errors", label)
		case pkg.IllTyped:
			return false, fmt.Sprintf("package %q is ill-typed", label)
		case pkg.Types == nil:
			return false, fmt.Sprintf("package %q has no type package", label)
		case pkg.TypesSizes == nil:
			return false, fmt.Sprintf("package %q has no type-size information", label)
		case len(pkg.CompiledGoFiles) > 0 && len(pkg.Syntax) != len(pkg.CompiledGoFiles):
			return false, fmt.Sprintf(
				"package %q dependency syntax count %d does not match compiled file count %d",
				label, len(pkg.Syntax), len(pkg.CompiledGoFiles),
			)
		case len(pkg.Syntax) > 0 && pkg.Fset == nil:
			return false, fmt.Sprintf("package %q has no file set", label)
		case len(pkg.Syntax) > 0 && pkg.TypesInfo == nil:
			return false, fmt.Sprintf("package %q has no type information", label)
		}
		for _, syntax := range pkg.Syntax {
			if syntax == nil {
				return false, fmt.Sprintf("package %q contains nil dependency syntax", label)
			}
		}
		importPaths := make([]string, 0, len(pkg.Imports))
		for importPath := range pkg.Imports {
			importPaths = append(importPaths, importPath)
		}
		sort.Strings(importPaths)
		for _, importPath := range importPaths {
			imported := pkg.Imports[importPath]
			if imported == nil {
				return false, fmt.Sprintf("package %q has no metadata for import %q", label, importPath)
			}
			queue = append(queue, imported)
		}
	}
	return true, ""
}

func buildGoCHAGraph(program *ssa.Program) (graph *callgraph.Graph, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%v", recovered)
			graph = nil
		}
	}()
	if program == nil {
		return nil, fmt.Errorf("SSA program is unavailable")
	}
	graph = cha.CallGraph(program)
	inlineGoSSASyntheticWrappers(graph)
	return graph, nil
}

func buildGoRTAGraph(roots []*ssa.Function) (graph *callgraph.Graph, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%v", recovered)
			graph = nil
		}
	}()
	result := rta.Analyze(roots, true)
	if result == nil || result.CallGraph == nil {
		return nil, fmt.Errorf("RTA returned no call graph")
	}
	inlineGoSSASyntheticWrappers(result.CallGraph)
	return result.CallGraph, nil
}

func buildGoVTAGraph(program *ssa.Program) (graph *callgraph.Graph, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%v", recovered)
			graph = nil
		}
	}()
	if program == nil {
		return nil, fmt.Errorf("SSA program is unavailable")
	}
	functions := ssautil.AllFunctions(program)
	if len(functions) == 0 {
		return nil, fmt.Errorf("SSA program contains no functions")
	}
	// VTA uses the sound CHA graph as its refinement boundary. Construct a
	// fresh graph here because the export-oriented CHA index inlines wrappers.
	graph = vta.CallGraph(functions, cha.CallGraph(program))
	if graph == nil {
		return nil, fmt.Errorf("VTA returned no call graph")
	}
	inlineGoSSASyntheticWrappers(graph)
	return graph, nil
}

// inlineGoSSASyntheticWrappers applies the reachability-preserving part of
// callgraph.Graph.DeleteSyntheticNodes, but deliberately keeps synthetic leaf
// functions. Deleting a leaf would silently remove an unknown candidate; by
// retaining it, the mapping pass can conservatively leave the source call
// unresolved when that target cannot be represented as a repository symbol.
func inlineGoSSASyntheticWrappers(graph *callgraph.Graph) {
	if graph == nil {
		return
	}
	edges := map[callgraph.Edge]bool{}
	for _, node := range graph.Nodes {
		for _, edge := range node.Out {
			edges[*edge] = true
		}
	}
	candidates := make([]*callgraph.Node, 0)
	for function, node := range graph.Nodes {
		if node == nil || node == graph.Root || function == nil || function.Syntax() != nil ||
			goSSAFunctionIsPackageInit(function) || len(node.Out) == 0 {
			continue
		}
		candidates = append(candidates, node)
	}
	sort.Slice(candidates, func(left, right int) bool {
		return candidates[left].Func.String() < candidates[right].Func.String()
	})
	for _, node := range candidates {
		if node == nil || node.Func == nil || graph.Nodes[node.Func] != node {
			continue
		}
		for _, incoming := range append([]*callgraph.Edge(nil), node.In...) {
			for _, outgoing := range append([]*callgraph.Edge(nil), node.Out...) {
				edge := callgraph.Edge{Caller: incoming.Caller, Site: incoming.Site, Callee: outgoing.Callee}
				if edges[edge] {
					continue
				}
				callgraph.AddEdge(edge.Caller, edge.Site, edge.Callee)
				edges[edge] = true
			}
		}
		graph.DeleteNode(node)
	}
}

func goSSAFunctionIsPackageInit(function *ssa.Function) bool {
	if function == nil || function.Package() == nil {
		return false
	}
	return function.Package().Func("init") == function
}

func goSSAMainPackages(initial []*ssa.Package) []*ssa.Package {
	filtered := make([]*ssa.Package, 0, len(initial))
	for _, pkg := range initial {
		if pkg != nil {
			filtered = append(filtered, pkg)
		}
	}
	mains := ssautil.MainPackages(filtered)
	sort.Slice(mains, func(left, right int) bool {
		leftPath, rightPath := "", ""
		if mains[left] != nil && mains[left].Pkg != nil {
			leftPath = mains[left].Pkg.Path()
		}
		if mains[right] != nil && mains[right].Pkg != nil {
			rightPath = mains[right].Pkg.Path()
		}
		if leftPath != rightPath {
			return leftPath < rightPath
		}
		return mains[left].String() < mains[right].String()
	})
	return mains
}

func goSSAMainRoots(mainPackage *ssa.Package) []*ssa.Function {
	if mainPackage == nil {
		return nil
	}
	var roots []*ssa.Function
	for _, name := range []string{"init", "main"} {
		if function := mainPackage.Func(name); function != nil {
			roots = append(roots, function)
		}
	}
	return roots
}

func newGoSSAGraphIndex() goSSAGraphIndex {
	return goSSAGraphIndex{
		sites:   map[goSSACallKey]bool{},
		targets: map[goSSACallKey]map[*ssa.Function]bool{},
	}
}

func indexGoSSAGraph(input *goSSAInput, graph *callgraph.Graph) goSSAGraphIndex {
	index := newGoSSAGraphIndex()
	if graph == nil {
		return index
	}
	for _, node := range graph.Nodes {
		if node == nil || node.Func == nil {
			continue
		}
		callerTypes := goSSAFunctionPackage(node.Func)
		if callerTypes == nil {
			continue
		}
		for _, block := range node.Func.Blocks {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common().Pos() == token.NoPos {
					continue
				}
				index.sites[goSSACallKey{input: input, callerTypes: callerTypes, position: site.Common().Pos()}] = true
			}
		}
	}
	for _, node := range graph.Nodes {
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Site == nil || edge.Caller == nil || edge.Caller.Func == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			if edge.Site.Common().Pos() == token.NoPos {
				continue
			}
			callerTypes := goSSAFunctionPackage(edge.Caller.Func)
			if callerTypes == nil {
				continue
			}
			key := goSSACallKey{input: input, callerTypes: callerTypes, position: edge.Site.Common().Pos()}
			if index.targets[key] == nil {
				index.targets[key] = map[*ssa.Function]bool{}
			}
			index.targets[key][edge.Callee.Func] = true
		}
	}
	return index
}

func mergeGoSSAGraphIndex(destination *goSSAGraphIndex, source goSSAGraphIndex) {
	for key := range source.sites {
		destination.sites[key] = true
	}
	for key, functions := range source.targets {
		if destination.targets[key] == nil {
			destination.targets[key] = map[*ssa.Function]bool{}
		}
		for function := range functions {
			destination.targets[key][function] = true
		}
	}
}

func goSSAFunctionPackage(function *ssa.Function) *types.Package {
	for current := function; current != nil; current = current.Parent() {
		if pkg := current.Package(); pkg != nil && pkg.Pkg != nil {
			return pkg.Pkg
		}
		if object := goSSAFunctionObject(current); object != nil && object.Pkg() != nil {
			return object.Pkg()
		}
	}
	return nil
}

func (e *goSemanticExtractor) selectGoSSAIndex(
	pending goSemanticPendingCall,
	key goSSACallKey,
	complete bool,
	chaIndex goSSAGraphIndex,
	rtaIndex goSSAGraphIndex,
	vtaRequested bool,
	vtaIndex goSSAGraphIndex,
	vtaFallback string,
) (string, string, string, goSSAGraphIndex) {
	if vtaRequested && vtaFallback == "" {
		if len(vtaIndex.targets[key]) > 0 {
			return "vta", "explicit_vta_profile", "none", vtaIndex
		}
		if vtaIndex.sites[key] {
			vtaFallback = "vta_empty_candidate_set_fallback"
		} else {
			vtaFallback = "vta_site_unavailable_fallback"
		}
	}
	algorithm, reason, index := e.selectDefaultGoSSAIndex(pending, key, complete, chaIndex, rtaIndex)
	if !vtaRequested {
		return algorithm, reason, "not_requested", index
	}
	return algorithm, reason, vtaFallback, index
}

func (e *goSemanticExtractor) selectDefaultGoSSAIndex(
	pending goSemanticPendingCall,
	key goSSACallKey,
	complete bool,
	chaIndex goSSAGraphIndex,
	rtaIndex goSSAGraphIndex,
) (string, string, goSSAGraphIndex) {
	if pending.context.typed.Name == "main" || pending.context.typed.ForTest != "" {
		if !complete {
			return "cha", "incomplete_program_fallback", chaIndex
		}
		if rtaIndex.sites[key] {
			return "rta", "main_or_test_program", rtaIndex
		}
		return "cha", "rta_site_unreachable_fallback", chaIndex
	}
	return "cha", "library_or_partial_program", chaIndex
}

func (e *goSemanticExtractor) mapGoSSAFunction(
	pending goSemanticPendingCall,
	function *ssa.Function,
	index goSSAGraphIndex,
	seen map[*ssa.Function]bool,
) ([]string, bool, bool) {
	if function == nil || seen[function] {
		return nil, false, true
	}
	seen[function] = true
	defer delete(seen, function)
	if pending.context.typed.ForTest == "" && goSSAFunctionIsTestOnly(function) {
		return nil, true, false
	}
	if goSSAFunctionHasAbstractReceiver(function) {
		// CHA may expose the abstract interface declaration next to the
		// concrete callees. It is not itself a callable repository target.
		return nil, true, false
	}

	if len(function.TypeArgs()) > 0 && goSSAFunctionHasOwnTypeParameters(function) {
		resolver := goSSAFunctionInstanceResolver(pending.context, function)
		nodeID := pending.context.visibleGoSSAFunctionInstance(resolver, goSSAFunctionObject(function))
		if nodeID == "" {
			return nil, false, true
		}
		return e.mappedGoSSANode(pending, nodeID)
	}
	if object := goSSAFunctionObject(function); object != nil {
		nodeID := e.symbolNodesByObject[object]
		if nodeID != "" && pending.context.ssaSymbolVisible(nodeID, object) {
			return e.mappedGoSSANode(pending, nodeID)
		}
		resolver := goSemanticFunctionResolver(object)
		if nodeID = pending.context.visibleSymbolNode(resolver, goSemanticFunctionPackagePath(object)); nodeID != "" {
			return e.mappedGoSSANode(pending, nodeID)
		}
	}
	if syntax := function.Syntax(); syntax != nil {
		if nodeID := e.symbolNodesBySyntax[syntax]; nodeID != "" {
			return e.mappedGoSSANode(pending, nodeID)
		}
	}
	if key, ok := e.goSSAFunctionSourceSpan(function); ok {
		if nodeID := e.closureNodesBySpan[key]; nodeID != "" {
			pkg := goSSAFunctionPackage(function)
			if pkg == nil || !pending.context.symbolNodeVisible(nodeID, pkg.Path()) {
				return nil, false, true
			}
			return e.mappedGoSSANode(pending, nodeID)
		}
	}
	return nil, false, true
}

func (e *goSemanticExtractor) goSSAFunctionSourceSpan(function *ssa.Function) (goSemanticSourceSpanKey, bool) {
	if function == nil || function.Syntax() == nil || function.Prog == nil || function.Prog.Fset == nil {
		return goSemanticSourceSpanKey{}, false
	}
	syntax := function.Syntax()
	start := function.Prog.Fset.PositionFor(syntax.Pos(), false)
	end := function.Prog.Fset.PositionFor(syntax.End(), false)
	startFile, ok := confinedMetadataFile(e.state.root, start.Filename)
	if !ok {
		return goSemanticSourceSpanKey{}, false
	}
	endFile, ok := confinedMetadataFile(e.state.root, end.Filename)
	if !ok || endFile != startFile {
		return goSemanticSourceSpanKey{}, false
	}
	return goSemanticSourceSpanFromEvidence(Evidence{
		Path:        relativePath(e.state.root, startFile),
		StartLine:   start.Line,
		StartColumn: start.Column,
		EndLine:     end.Line,
		EndColumn:   end.Column,
	})
}

func (p *goSemanticPackage) visibleGoSSAFunctionInstance(resolver string, object *types.Func) string {
	if p == nil || object == nil {
		return ""
	}
	resolvers := []string{resolver}
	importPath := goSemanticFunctionPackagePath(object)
	if _, rewritten, replaced := p.extractor.state.moduleResolution.replacementImport(p.moduleDir(), importPath); replaced {
		if rewrittenResolver := goSemanticRewriteResolver(resolver, importPath, rewritten); rewrittenResolver != resolver {
			resolvers = append(resolvers, rewrittenResolver)
		}
	}
	for _, candidate := range resolvers {
		nodeID := p.extractor.functionInstances[candidate]
		if nodeID != "" && p.ssaSymbolVisible(nodeID, object) {
			return nodeID
		}
	}
	return ""
}

func (e *goSemanticExtractor) mappedGoSSANode(pending goSemanticPendingCall, nodeID string) ([]string, bool, bool) {
	if nodeID == "" || e.state.nodes[nodeID].Kind != "symbol" {
		return nil, false, true
	}
	pendingVariant := goSemanticConditionValue(pending.condition, "go.package_variant")
	variants := e.symbolVariants[nodeID]
	if len(variants) > 0 && !variants[""] && !variants[pendingVariant] {
		return nil, true, false
	}
	return []string{nodeID}, true, true
}

func (e *goSemanticExtractor) registerSymbolVariant(nodeID string, condition Condition) {
	if nodeID == "" || e.state.nodes[nodeID].Kind != "symbol" {
		return
	}
	if e.symbolVariants[nodeID] == nil {
		e.symbolVariants[nodeID] = map[string]bool{}
	}
	variant := goSemanticConditionValue(condition, "go.package_variant")
	e.symbolVariants[nodeID][variant] = true
}

func goSSAFunctionHasAbstractReceiver(function *ssa.Function) bool {
	if function == nil {
		return false
	}
	object := goSSAFunctionObject(function)
	if object == nil {
		return false
	}
	signature, _ := object.Type().(*types.Signature)
	return signature != nil && signature.Recv() != nil && goSemanticDynamicReceiver(signature.Recv().Type())
}

func goSSAFunctionObject(function *ssa.Function) *types.Func {
	if function == nil {
		return nil
	}
	if object, ok := function.Object().(*types.Func); ok {
		return object
	}
	if origin := function.Origin(); origin != nil {
		object, _ := origin.Object().(*types.Func)
		return object
	}
	return nil
}

func goSSAFunctionHasOwnTypeParameters(function *ssa.Function) bool {
	object := goSSAFunctionObject(function)
	if object == nil {
		return false
	}
	signature, _ := object.Type().(*types.Signature)
	return signature != nil && signature.TypeParams() != nil && signature.TypeParams().Len() > 0
}

func goSSAFunctionInstanceResolver(context *goSemanticPackage, function *ssa.Function) string {
	object := goSSAFunctionObject(function)
	if context == nil || object == nil {
		return ""
	}
	arguments := make([]string, 0, len(function.TypeArgs()))
	for _, argument := range function.TypeArgs() {
		arguments = append(arguments, context.typeArgumentIdentity(argument))
	}
	return goSemanticFunctionResolver(object) + "[" + strings.Join(arguments, ",") + "]"
}

func goSSAFunctionIsTestOnly(function *ssa.Function) bool {
	if function == nil || function.Prog == nil || function.Prog.Fset == nil {
		return false
	}
	positions := []token.Pos{function.Pos()}
	if syntax := function.Syntax(); syntax != nil {
		positions = append(positions, syntax.Pos())
	}
	if object := goSSAFunctionObject(function); object != nil {
		positions = append(positions, object.Pos())
	}
	if function.Signature != nil && function.Signature.Recv() != nil {
		if named, _ := goSemanticReceiverNamed(function.Signature.Recv().Type()); named != nil && named.Obj() != nil {
			positions = append(positions, named.Obj().Pos())
		}
	}
	for _, position := range positions {
		if position == token.NoPos {
			continue
		}
		filename := function.Prog.Fset.PositionFor(position, false).Filename
		if strings.HasSuffix(filepath.ToSlash(filename), "_test.go") {
			return true
		}
	}
	return false
}

func (p *goSemanticPackage) ssaSymbolVisible(nodeID string, object *types.Func) bool {
	if object == nil || object.Pkg() == nil {
		return p.extractor.state.nodes[nodeID].Kind == "symbol"
	}
	return p.symbolNodeVisible(nodeID, object.Pkg().Path())
}

func goSSACandidateEvidence(
	pending goSemanticPendingCall,
	algorithm, selectionReason, fallbackReason string,
	candidateCount int,
	vtaRequested bool,
) []Evidence {
	evidence := append([]Evidence(nil), pending.evidence...)
	if len(evidence) == 0 {
		return evidence
	}
	primary := evidence[0]
	properties := make(map[string]any, len(primary.Properties)+7)
	for key, value := range primary.Properties {
		properties[key] = value
	}
	properties["algorithm"] = algorithm
	properties["selection_reason"] = selectionReason
	properties["analysis_scope"] = map[string]string{
		"rta": "complete_program", "cha": "partial_program", "vta": "complete_program",
	}[algorithm]
	properties["candidate_count"] = candidateCount
	properties["fallback_reason"] = fallbackReason
	if vtaRequested {
		properties["requested_algorithm"] = "vta"
	} else {
		properties["requested_algorithm"] = "rta-cha"
	}
	primary.Extractor = "go-ssa"
	primary.ExtractorVersion = AdapterVersion
	primary.Properties = properties
	evidence[0] = primary
	return evidence
}

func (e *goSemanticExtractor) addSSABuildDiagnostic(input *goSSAInput, err error) {
	path := "go.mod"
	if input != nil && input.ModuleRelativeDir != "" && input.ModuleRelativeDir != "." {
		path = filepath.ToSlash(filepath.Join(input.ModuleRelativeDir, "go.mod"))
	}
	detail := normalizeGoPackagesMessage(e.state.root, err.Error())
	message := "Go SSA call graph could not be constructed; dynamic calls remain unresolved: " + detail
	identity := map[string]any{"code": "go_ssa_build_failed", "path": path, "profile_id": e.state.profile.ID, "message": message}
	diagnostic := Diagnostic{
		ID: stableIDFromValue("diagnostic", identity), Code: "go_ssa_build_failed", Severity: "warning",
		Message: message, ProfileID: e.state.profile.ID, Path: path, Recoverable: true,
	}
	if !e.diagnosticIDs[diagnostic.ID] {
		e.diagnosticIDs[diagnostic.ID] = true
		e.state.diagnostics = append(e.state.diagnostics, diagnostic)
	}
}

func (e *goSemanticExtractor) addSSAPartialDiagnostic(input *goSSAInput, reason string, vtaRequested bool) {
	path := "go.mod"
	if input != nil && input.ModuleRelativeDir != "" && input.ModuleRelativeDir != "." {
		path = filepath.ToSlash(filepath.Join(input.ModuleRelativeDir, "go.mod"))
	}
	requested := "RTA"
	fallbackReason := "incomplete_program_fallback"
	if vtaRequested {
		requested = "VTA/RTA"
		fallbackReason = "vta_incomplete_program_fallback"
	}
	message := "Go SSA dependency bodies are incomplete; CHA is used instead of " + requested + ": " + normalizeGoPackagesMessage(e.state.root, reason)
	identity := map[string]any{
		"code": "go_ssa_partial_program", "path": path, "profile_id": e.state.profile.ID,
		"reason": reason,
	}
	diagnostic := Diagnostic{
		ID: stableIDFromValue("diagnostic", identity), Code: "go_ssa_partial_program", Severity: "warning",
		Message: message, ProfileID: e.state.profile.ID, Path: path,
		Properties: map[string]any{
			"algorithm": "cha", "reason": "incomplete_program", "fallback_reason": fallbackReason,
		}, Recoverable: true,
	}
	if !e.diagnosticIDs[diagnostic.ID] {
		e.diagnosticIDs[diagnostic.ID] = true
		e.state.diagnostics = append(e.state.diagnostics, diagnostic)
	}
}

func (e *goSemanticExtractor) addSSAVTAFallbackDiagnostic(input *goSSAInput, err error) {
	path := "go.mod"
	if input != nil && input.ModuleRelativeDir != "" && input.ModuleRelativeDir != "." {
		path = filepath.ToSlash(filepath.Join(input.ModuleRelativeDir, "go.mod"))
	}
	detail := normalizeGoPackagesMessage(e.state.root, err.Error())
	message := "Go VTA construction failed; the default RTA/CHA policy is used: " + detail
	identity := map[string]any{
		"code": "go_ssa_vta_fallback", "path": path, "profile_id": e.state.profile.ID,
		"reason": "vta_construction_failed_fallback", "message": message,
	}
	diagnostic := Diagnostic{
		ID: stableIDFromValue("diagnostic", identity), Code: "go_ssa_vta_fallback", Severity: "warning",
		Message: message, ProfileID: e.state.profile.ID, Path: path, Recoverable: true,
		Properties: map[string]any{
			"requested_algorithm": "vta", "fallback_algorithm": "rta-cha",
			"fallback_reason": "vta_construction_failed_fallback",
		},
	}
	if !e.diagnosticIDs[diagnostic.ID] {
		e.diagnosticIDs[diagnostic.ID] = true
		e.state.diagnostics = append(e.state.diagnostics, diagnostic)
	}
}

func (e *goSemanticExtractor) addSSASiteDiagnostic(pending goSemanticPendingCall, code, message string, properties map[string]any) {
	if len(pending.evidence) == 0 {
		return
	}
	primary := pending.evidence[0]
	identity := map[string]any{
		"code": code, "path": pending.file.Path, "profile_id": e.state.profile.ID,
		"span": goSemanticSpan(primary),
	}
	diagnostic := Diagnostic{
		ID: stableIDFromValue("diagnostic", identity), Code: code, Severity: "warning", Message: message,
		ProfileID: e.state.profile.ID, Path: pending.file.Path,
		StartLine: primary.StartLine, StartColumn: primary.StartColumn,
		EndLine: primary.EndLine, EndColumn: primary.EndColumn,
		Evidence: append([]Evidence(nil), pending.evidence...), Properties: properties, Recoverable: true,
	}
	if !e.diagnosticIDs[diagnostic.ID] {
		e.diagnosticIDs[diagnostic.ID] = true
		e.state.diagnostics = append(e.state.diagnostics, diagnostic)
	}
}
