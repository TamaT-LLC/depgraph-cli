package worker

import (
	"reflect"
	"testing"
)

// TestGoReferenceNodesCarryTheOwningUnitLocation pins #596 across analysis
// units: a dependency loaded from export data emits reference nodes with the
// same IDs as the unit that owns the declarations, and the core rejects a node
// whose properties differ between units. Every node the package-scope unit
// emits must therefore equal the module-whole-program node, including
// source_path and source_span of top-level declarations, methods (value,
// pointer and generic receivers), named and embedded fields, interface
// methods, grouped constants and variables, and generic instances.
func TestGoReferenceNodesCarryTheOwningUnitLocation(t *testing.T) {
	const module = "example.com/loc"
	root := goLoaderTestFixture(t, map[string]string{
		"go.mod": "module " + module + "\n\ngo 1.26.1\n",
		"dep/dep.go": `package dep

type Base struct{ ID int }

type Generic[T any] struct{ Value T }

func (g *Generic[T]) Get() T { return g.Value }

type Pair[K comparable, V any] struct {
	Key K
	Val V
}

func (p Pair[K, V]) First() K { return p.Key }

type Iface interface {
	Run() int
}

type Wrapper struct {
	Base
	*Generic[int]
	Name, Tag string
}

func (w Wrapper) Run() int { return w.ID }

const (
	A = 1
	B = 2
)

var X, Y = 3, 4

func Make[T any](v T) Generic[T] { return Generic[T]{Value: v} }
`,
		"use/use.go": `package use

import "example.com/loc/dep"

func Use() int {
	w := dep.Wrapper{Name: "n", Tag: "t", Generic: &dep.Generic[int]{}}
	w.ID = dep.A + dep.B + dep.X + dep.Y
	w.Value = w.Get()
	g := dep.Make(1)
	p := dep.Pair[string, int]{Key: "k", Val: 1}
	var i dep.Iface = w
	return i.Run() + g.Get() + w.Run() + len(w.Tag+w.Name+p.First()) + w.Base.ID
}
`,
	})
	request := AnalysisUnitRequest{
		ContractVersion:    AnalysisUnitContractVersion,
		UnitID:             "analysis-unit:use",
		Adapter:            AdapterName,
		UnitRoot:           ".",
		SourcePaths:        []string{"use/use.go"},
		Stage:              AnalysisUnitStageSemantic,
		ContextPaths:       []string{"dep/dep.go", "use/use.go"},
		ChunkID:            "use",
		ChunkCount:         1,
		ContextFingerprint: "use-context",
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("request.Validate() error = %v", err)
	}
	scan := func(options scanOptions) Result {
		t.Helper()
		result, err := scanWithOptions(root, nil, &request, nil, options)
		if err != nil {
			t.Fatalf("scanWithOptions(%+v) error = %v", options, err)
		}
		if !containsString(result.Coverage.Completeness, "semantic-complete") {
			t.Fatalf("scan(%+v) coverage = %+v, diagnostics = %+v", options, result.Coverage, result.Diagnostics)
		}
		return result
	}
	whole := scan(scanOptions{})
	scoped := scan(scanOptions{loaderMode: goLoaderModePackage, loaderTargets: []goLoaderTargetSpec{{Dir: "use"}}})
	if got := scoped.Profile.Properties["go_loader_reference_packages_in_repo"]; got != "1" {
		t.Fatalf("go_loader_reference_packages_in_repo = %q, want 1", got)
	}

	wholeNodes := goLoaderNodesByID(whole)
	depLocator := goSemanticPackageLocator(goTypedPackage{ID: module + "/dep", PkgPath: module + "/dep", ModulePath: module, ModuleRelativeDir: "."})
	located := map[string]bool{}
	for _, node := range scoped.Nodes {
		counterpart, ok := wholeNodes[node.ID]
		if !ok {
			t.Fatalf("package-scope node is missing from the whole-program run: %+v", node)
		}
		if !reflect.DeepEqual(node, counterpart) {
			t.Fatalf("node %s differs between units:\n scoped=%+v\n whole =%+v", node.ID, node, counterpart)
		}
		if node.Properties["package_locator"] != depLocator || (node.Kind != "symbol" && node.Kind != "type") {
			continue
		}
		if node.Properties["source_path"] != "dep/dep.go" || node.Properties["source_span"] == nil {
			t.Fatalf("dependency node has no declaration location: %+v", node)
		}
		located[node.Locator] = true
	}
	for _, locator := range []string{
		"go-type:" + module + "/dep.Wrapper",
		"go-type:" + module + "/dep.Iface",
		"go-symbol:" + module + "/dep.Wrapper.Base",
		"go-symbol:" + module + "/dep.Wrapper.Generic",
		"go-symbol:" + module + "/dep.Wrapper.Tag",
		"go-symbol:" + module + "/dep.Base.ID",
		"go-symbol:" + module + "/dep.(Wrapper).Run",
		"go-symbol:" + module + "/dep.(*Generic).Get",
		"go-symbol:" + module + "/dep.(Pair).First",
		"go-symbol:" + module + "/dep.A",
		"go-symbol:" + module + "/dep.Y",
		"go-symbol:" + module + "/dep.Generic.Value",
		"go-symbol:" + module + "/dep.Make[int]",
		"go-type:" + module + "/dep.Generic[int]",
		"go-type:" + module + "/dep.Pair[string,int]",
	} {
		if !located[locator] {
			t.Errorf("located dependency nodes do not include %s; got %v", locator, located)
		}
	}
}

func TestGoReferenceDeclarationLocationsDropAmbiguousKeys(t *testing.T) {
	root := goLoaderTestFixture(t, map[string]string{
		"dep/a.go": "package dep\n\nfunc init() {}\n\nvar Shared = 1\n\ntype T struct{ _ int }\n",
		"dep/b.go": "package dep\n\nfunc init() {}\n\nvar Shared = 2\n\nfunc (*T) M() {}\n",
	})
	locations := goReferenceDeclarationLocations(root, []string{root + "/dep/a.go", root + "/dep/b.go", root + "/../outside.go"})
	if _, ok := locations["Shared"]; ok {
		t.Fatalf("a key declared twice was located: %+v", locations["Shared"])
	}
	for _, key := range []string{"init", "T._"} {
		if _, ok := locations[key]; ok {
			t.Fatalf("%s was located", key)
		}
	}
	want := goSemanticSourceSpanKey{path: "dep/b.go", startLine: 7, startColumn: 11, endLine: 7, endColumn: 12}
	if got := locations["T.M"]; got != want {
		t.Fatalf("T.M = %+v, want %+v", got, want)
	}
}
