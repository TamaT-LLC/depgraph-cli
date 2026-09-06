package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	semanticModulePath             = "example.com/semantic"
	semanticPackagePath            = semanticModulePath + "/model"
	semanticPackageLocator         = "go:" + semanticModulePath + "@workspace#" + semanticPackagePath
	semanticExternalTestPath       = semanticPackagePath + "_test"
	semanticExternalTestLocator    = "go:" + semanticModulePath + "@workspace#" + semanticExternalTestPath
	semanticModelRelativePath      = "model/model.go"
	semanticGoodPackageLocator     = "go:example.com/good@workspace#good#example.com/good"
	semanticEvidenceExtractor      = "go-types"
	semanticParserFallbackCoverage = "go-packages-parser-fallback"
)

func TestGoSemanticGraphCoversObjectsTypesAndTestVariants(t *testing.T) {
	result := semanticScanFixture(t)

	if got := result.Profile.Properties["go_packages_status"]; got != "loaded" {
		t.Fatalf("go_packages_status = %q, want loaded; diagnostics=%+v", got, result.Diagnostics)
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("semantic scan reported project code execution")
	}
	if !containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("semantic completeness missing: %+v", result.Coverage)
	}

	build := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".Build")
	workerType := semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".Worker")
	semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".Resettable")
	semanticFindNamedNode(t, result, "type", "struct", semanticPackagePath+".Service")
	concreteWork := semanticFindNamedNode(t, result, "symbol", "method", semanticPackagePath+".(Service).Work")
	semanticFindNamedNode(t, result, "symbol", "method", semanticPackagePath+".(*Service).Close")
	interfaceWork := semanticFindNamedNode(t, result, "symbol", "method", semanticPackagePath+".(Worker).Work")
	internalTest := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".TestInternal")
	externalTest := semanticFindNamedNode(t, result, "symbol", "function", semanticExternalTestPath+".TestExternal")

	for name, node := range map[string]Node{
		"Build":        build,
		"Worker":       workerType,
		"Service.Work": concreteWork,
		"Worker.Work":  interfaceWork,
		"TestInternal": internalTest,
		"TestExternal": externalTest,
	} {
		if node.ID == "" {
			t.Fatalf("%s node has an empty ID", name)
		}
	}
	if concreteWork.ID == interfaceWork.ID {
		t.Fatalf("concrete and interface methods share an ID: %s", concreteWork.ID)
	}
	if got := semanticStringProperty(t, build, "package_locator"); got != semanticPackageLocator {
		t.Fatalf("Build package locator = %q, want %q", got, semanticPackageLocator)
	}
	if got := semanticStringProperty(t, internalTest, "package_locator"); got != semanticPackageLocator {
		t.Fatalf("internal test package locator = %q, want %q", got, semanticPackageLocator)
	}
	if got := semanticStringProperty(t, externalTest, "package_locator"); got != semanticExternalTestLocator {
		t.Fatalf("external test package locator = %q, want %q", got, semanticExternalTestLocator)
	}
	semanticRequireConditionalRelation(t, result, "declares", "", internalTest.ID, "go.package_variant", "internal_test")
	externalDeclaration := semanticRequireConditionalRelation(t, result, "declares", "", externalTest.ID, "go.package_variant", "external_test")
	if source := semanticNodeByID(t, result, externalDeclaration.Source); source.Kind != "module" || source.Locator != "go-package:"+semanticPackagePath {
		t.Fatalf("external-test declaration is not owned by its base package: edge=%+v source=%+v", externalDeclaration, source)
	}

	canonicalIdentities := map[string]string{}
	buildCount := 0
	semanticNodeCount := 0
	for _, node := range result.Nodes {
		if node.Kind != "symbol" && node.Kind != "type" {
			continue
		}
		semanticNodeCount++
		identity, canonical := semanticAssertNodeContract(t, node)
		key := node.Kind + "\x00" + canonical
		if previous, exists := canonicalIdentities[key]; exists && previous != node.ID {
			t.Fatalf("canonical identity maps to multiple IDs: %s and %s (%s)", previous, node.ID, canonical)
		}
		canonicalIdentities[key] = node.ID
		if identity["resolver_identity"] == semanticPackagePath+".Build" {
			buildCount++
		}
	}
	if semanticNodeCount == 0 {
		t.Fatal("scan emitted no semantic nodes")
	}
	if buildCount != 1 {
		t.Fatalf("Build declaration was emitted %d times across package variants, want 1", buildCount)
	}

	semanticAssertCoverageLedger(t, result)
	semanticAssertAllStrictTypeUses(t, result)
	semanticSitesInModel := 0
	for _, site := range result.Sites {
		if len(site.Evidence) > 0 && site.Evidence[0].Kind == "semantic" && site.Evidence[0].Path == semanticModelRelativePath {
			semanticSitesInModel++
		}
	}
	if semanticSitesInModel == 0 {
		t.Fatal("model/model.go has no semantic dependency sites")
	}
	completion := semanticFileCompletion(t, result, semanticModelRelativePath)
	if completion.EmittedSites != semanticSitesInModel {
		t.Fatalf("model/model.go emitted site ledger = %d, want %d semantic sites: %+v", completion.EmittedSites, semanticSitesInModel, completion)
	}
}

func TestGoSemanticFixtureMatchesExpectedGraph(t *testing.T) {
	result := semanticScanFixture(t)
	contractPath := filepath.Join(semanticFixtureRoot(t), "expected-graph.json")
	encoded, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read semantic fixture contract: %v", err)
	}
	var contract semanticFixtureExpectedGraph
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("decode semantic fixture contract: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("semantic fixture contract has trailing JSON: %v", err)
	}
	if contract.SchemaVersion != "1.0" || contract.Scope != "required_semantic_subgraph" || len(contract.Nodes) == 0 || len(contract.Relations) == 0 {
		t.Fatalf("semantic fixture contract is empty or unsupported: %+v", contract)
	}

	nodesByLocator := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		if previous, duplicate := nodesByLocator[node.Locator]; duplicate && previous.ID != node.ID {
			t.Fatalf("fixture locator %q maps to multiple nodes: %s and %s", node.Locator, previous.ID, node.ID)
		}
		nodesByLocator[node.Locator] = node
	}
	for _, expected := range contract.Nodes {
		node, ok := nodesByLocator[expected.Locator]
		if !ok {
			t.Fatalf("fixture expected node %q was not emitted", expected.Locator)
		}
		if node.Kind != expected.Kind || semanticNodeKind(node) != expected.SemanticKind {
			t.Fatalf("fixture node %q = %s/%s, want %s/%s", expected.Locator, node.Kind, semanticNodeKind(node), expected.Kind, expected.SemanticKind)
		}
	}

	for _, expected := range contract.Relations {
		source, sourceOK := nodesByLocator[expected.SourceLocator]
		target, targetOK := nodesByLocator[expected.TargetLocator]
		if !sourceOK || !targetOK {
			t.Fatalf("fixture relation %s -> %s references missing nodes", expected.SourceLocator, expected.TargetLocator)
		}
		matched := 0
		for _, edge := range result.Edges {
			if edge.Source != source.ID || edge.Target != target.ID || edge.Kind != expected.Kind ||
				!semanticFixtureEvidenceMatches(edge.Evidence, expected.Evidence) {
				continue
			}
			matched++
			if edge.Phase != expected.Phase || edge.ResolutionStatus != expected.ResolutionStatus || edge.Precision != expected.Precision {
				t.Fatalf("fixture edge %s -> %s has invalid relation contract: %+v", expected.SourceLocator, expected.TargetLocator, edge)
			}
			if edge.SiteID == "" {
				t.Fatalf("fixture dependency edge %s -> %s has no site", expected.SourceLocator, expected.TargetLocator)
			}
			site := semanticSiteByID(t, result, edge.SiteID)
			if site.Source != source.ID || site.Kind != expected.SiteKind ||
				site.ResolutionStatus != expected.ResolutionStatus || site.Precision != expected.Precision ||
				!containsString(site.TargetIDs, target.ID) || !semanticFixtureEvidenceMatches(site.Evidence, expected.Evidence) {
				t.Fatalf("fixture site disagrees with expected relation %s -> %s: %+v", expected.SourceLocator, expected.TargetLocator, site)
			}
		}
		if matched == 0 {
			t.Fatalf("fixture expected relation %s --%s--> %s was not emitted", expected.SourceLocator, expected.Kind, expected.TargetLocator)
		}
	}
}

type semanticFixtureExpectedGraph struct {
	SchemaVersion string                            `json:"schema_version"`
	Scope         string                            `json:"scope"`
	Nodes         []semanticFixtureExpectedNode     `json:"nodes"`
	Relations     []semanticFixtureExpectedRelation `json:"relations"`
}

type semanticFixtureExpectedNode struct {
	Locator      string `json:"locator"`
	Kind         string `json:"kind"`
	SemanticKind string `json:"semantic_kind"`
}

type semanticFixtureExpectedRelation struct {
	SourceLocator    string                          `json:"source_locator"`
	TargetLocator    string                          `json:"target_locator"`
	SiteKind         string                          `json:"site_kind"`
	Kind             string                          `json:"kind"`
	Phase            string                          `json:"phase"`
	ResolutionStatus string                          `json:"resolution_status"`
	Precision        string                          `json:"precision"`
	Evidence         semanticFixtureExpectedEvidence `json:"evidence"`
}

type semanticFixtureExpectedEvidence struct {
	Kind             string            `json:"kind"`
	Extractor        string            `json:"extractor"`
	ExtractorVersion string            `json:"extractor_version"`
	Path             string            `json:"path"`
	StartLine        int               `json:"start_line"`
	StartColumn      int               `json:"start_column"`
	EndLine          int               `json:"end_line"`
	EndColumn        int               `json:"end_column"`
	Properties       map[string]string `json:"properties"`
}

func semanticFixtureEvidenceMatches(actual []Evidence, expected semanticFixtureExpectedEvidence) bool {
	if len(actual) == 0 {
		return false
	}
	primary := actual[0]
	if primary.Kind != expected.Kind || primary.Extractor != expected.Extractor ||
		primary.ExtractorVersion != expected.ExtractorVersion || primary.Path != expected.Path ||
		primary.StartLine != expected.StartLine || primary.StartColumn != expected.StartColumn ||
		primary.EndLine != expected.EndLine || primary.EndColumn != expected.EndColumn {
		return false
	}
	for key, value := range expected.Properties {
		if actualValue, ok := primary.Properties[key].(string); !ok || actualValue != value {
			return false
		}
	}
	return true
}

func TestGoSemanticIdentitiesRelationsAndGenericOrder(t *testing.T) {
	result := semanticScanFixture(t)

	build := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".Build")
	input := semanticFindNamedNode(t, result, "type", "struct", semanticPackagePath+".Input")
	output := semanticFindNamedNode(t, result, "type", "struct", semanticPackagePath+".Output")
	workerType := semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".Worker")
	resettableType := semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".Resettable")
	aliasResettableType := semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".AliasResettable")
	internalWorkerType := semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".internalWorker")
	internalOnlyType := semanticFindNamedNode(t, result, "type", "struct", semanticPackagePath+".internalOnly")
	externalOnlyType := semanticFindNamedNode(t, result, "type", "interface", semanticExternalTestPath+".externalOnly")
	serviceType := semanticFindNamedNode(t, result, "type", "struct", semanticPackagePath+".Service")
	concreteWork := semanticFindNamedNode(t, result, "symbol", "method", semanticPackagePath+".(Service).Work")

	localOutput := semanticFindLocalNode(t, result, "local_variable", "output")
	localIdentity, _ := semanticAssertNodeContract(t, localOutput)
	if got := localIdentity["identity_kind"]; got != "local" {
		t.Fatalf("local identity_kind = %#v, want local", got)
	}
	if got := localIdentity["enclosing_symbol"]; got != build.ID {
		t.Fatalf("local enclosing_symbol = %#v, want %s", got, build.ID)
	}
	if got := localIdentity["relative_path"]; got != semanticModelRelativePath {
		t.Fatalf("local relative_path = %#v, want %q", got, semanticModelRelativePath)
	}
	semanticAssertIdentitySpan(t, localIdentity, 44, 2, 44, 8)

	semanticRequireSiteLessRelation(t, result, "declares", "", build.ID)
	semanticRequireSiteLessRelation(t, result, "declares", "", workerType.ID)
	semanticRequireSiteLessRelation(t, result, "declares", "", serviceType.ID)
	semanticRequireSiteLessRelation(t, result, "declares", "", concreteWork.ID)
	semanticRequireSiteLessRelation(t, result, "declares", build.ID, localOutput.ID)
	semanticRequireSiteLessRelation(t, result, "extends", resettableType.ID, workerType.ID)
	semanticRequireSiteLessRelation(t, result, "extends", aliasResettableType.ID, workerType.ID)
	semanticRequireSiteLessRelation(t, result, "implements", serviceType.ID, workerType.ID)
	semanticRequireSiteLessRelation(t, result, "implements", serviceType.ID, resettableType.ID)
	semanticRequireConditionalRelation(t, result, "implements", serviceType.ID, internalWorkerType.ID, "go.package_variant", "internal_test")
	semanticForbidRelation(t, result, "implements", internalOnlyType.ID, externalOnlyType.ID)

	pairInstance := semanticFindGenericInstance(t, result, "type", semanticPackagePath+".Pair", []string{
		semanticPackagePath + ".Output",
		semanticPackagePath + ".Input",
	})
	convertInstance := semanticFindGenericInstance(t, result, "symbol", semanticPackagePath+".Convert", []string{
		semanticPackagePath + ".Output",
		semanticPackagePath + ".Input",
	})
	semanticRequireSiteLessRelation(t, result, "instantiates", build.ID, pairInstance.ID)
	semanticRequireSiteLessRelation(t, result, "instantiates", build.ID, convertInstance.ID)
	getterInstance := semanticFindGenericInstance(t, result, "type", semanticPackagePath+".Getter", []string{"int"})
	intGetter := semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".IntGetter")
	semanticRequireSiteLessRelation(t, result, "implements", getterInstance.ID, intGetter.ID)

	semanticRequireStrictTypeUse(t, result, concreteWork.ID, input.ID)
	semanticRequireStrictTypeUse(t, result, concreteWork.ID, output.ID)
	semanticRequireInitializerTypeUse(t, result, workerType.ID)
	semanticRequirePackageInitializers(t, result, 6)
	semanticRequireAnonymousMembersNotNamed(t, result, "Ghost", "Phantom")
	semanticRequireDistinctScopedTypeArguments(t, result, semanticPackagePath+".Convert", 2)
	semanticRequireGenericInstanceCount(t, result, semanticPackagePath+".FuncBox", 1)
	semanticRequireGenericInstanceCount(t, result, semanticPackagePath+".InterfaceBox", 1)

	genericMatcher := semanticFindNamedNode(t, result, "type", "struct", semanticPackagePath+".GenericMatcher")
	genericMatch := semanticFindNamedNode(t, result, "type", "interface", semanticPackagePath+".GenericMatch")
	semanticForbidRelation(t, result, "implements", genericMatcher.ID, genericMatch.ID)
	genericMatcherInstance := semanticFindGenericInstance(t, result, "type", semanticPackagePath+".GenericMatcher", []string{"int"})
	genericMatchInstance := semanticFindGenericInstance(t, result, "type", semanticPackagePath+".GenericMatch", []string{"int"})
	semanticRequireSiteLessRelation(t, result, "implements", genericMatcherInstance.ID, genericMatchInstance.ID)
	semanticRequireScopedGenericImplements(t, result, semanticPackagePath+".ScopedBox", semanticPackagePath+".ScopedContract", 2)
}

func TestGoSemanticDirectCallsAreStrictAndConservative(t *testing.T) {
	result := semanticScanFixture(t)
	semanticAssertAllStrictCalls(t, result)

	direct := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".DirectCallMatrix")
	externalCall := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".ExternalCall")
	method := semanticFindNamedNode(t, result, "symbol", "method", semanticPackagePath+".(MethodExpressionTarget).Execute")
	inferred := semanticFindGenericInstance(t, result, "symbol", semanticPackagePath+".InferredCall", []string{"int"})

	directExternalCalls := 0
	closureExternalCalls := 0
	packageExternalCalls := 0
	methodCalls := 0
	inferredCalls := 0
	closureCalls := 0
	callFileUnresolved := map[string]int{}
	callFileCandidates := map[string]int{}
	callFileDiagnostics := map[string]bool{}
	conversionSite := false
	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	for _, edge := range result.Edges {
		if edge.Kind != "calls" {
			continue
		}
		site := semanticSiteByID(t, result, edge.SiteID)
		primary := site.Evidence[0]
		if primary.Path == "model/calls.go" && primary.StartLine == 48 {
			conversionSite = true
		}
		if primary.Path == "model/calls.go" && site.ResolutionStatus == "unresolved" {
			callFileUnresolved[site.Reason]++
		}
		if edge.Target == externalCall.ID && primary.Path == "model/calls.go" {
			switch semanticNodeKind(nodes[edge.Source]) {
			case "function":
				if edge.Source != direct.ID {
					t.Fatalf("ExternalCall has unexpected function caller: %+v", edge)
				}
				directExternalCalls++
			case "closure":
				closureExternalCalls++
			case "package_initializer":
				packageExternalCalls++
			default:
				t.Fatalf("ExternalCall has invalid caller: edge=%+v source=%+v", edge, nodes[edge.Source])
			}
		}
		if edge.Source == direct.ID && edge.Target == method.ID {
			methodCalls++
		}
		if edge.Source == direct.ID && edge.Target == inferred.ID {
			inferredCalls++
		}
		if edge.Source == direct.ID && semanticNodeKind(nodes[edge.Target]) == "closure" {
			closureCalls++
		}
	}
	if directExternalCalls != 2 || closureExternalCalls != 1 || packageExternalCalls != 1 {
		t.Fatalf("ExternalCall callers = direct:%d closure:%d package:%d, want 2/1/1", directExternalCalls, closureExternalCalls, packageExternalCalls)
	}
	if methodCalls != 2 || inferredCalls != 1 || closureCalls != 1 {
		t.Fatalf("exact direct calls = method:%d inferred:%d closure:%d, want 2/1/1", methodCalls, inferredCalls, closureCalls)
	}
	if conversionSite {
		t.Fatal("type conversion was emitted as a call site")
	}
	if !reflect.DeepEqual(callFileUnresolved, map[string]int{
		"function_value_dispatch": 3, "reflection_call_target_boundary": 1,
	}) {
		t.Fatalf("calls.go unresolved classifications = %v", callFileUnresolved)
	}
	externalResolvers := map[string]bool{}
	for _, site := range result.Sites {
		if site.Kind == "call" && len(site.Evidence) > 0 && site.Evidence[0].Path == "model/calls.go" && site.ResolutionStatus == "candidates" {
			dispatch, _ := site.Evidence[0].Properties["dispatch"].(string)
			callFileCandidates[dispatch]++
			if dispatch == "function_value" && !reflect.DeepEqual(site.TargetIDs, []string{externalCall.ID}) {
				t.Fatalf("known function-value candidate targets = %v, want ExternalCall", site.TargetIDs)
			}
		}
		if site.Kind != "call" || len(site.Evidence) == 0 || site.Evidence[0].Path != "model/calls.go" || site.ResolutionStatus != "external" {
			continue
		}
		target := nodes[site.TargetIDs[0]]
		resolver, _ := target.Properties["resolver_identity"].(string)
		externalResolvers[resolver] = true
	}
	if !reflect.DeepEqual(callFileCandidates, map[string]int{"interface": 2, "function_value": 1}) {
		t.Fatalf("calls.go candidate sites by dispatch = %v, want two interface and one function-value candidate", callFileCandidates)
	}
	for _, resolver := range []string{"fmt.Sprintf", "builtin.println", "reflect.ValueOf"} {
		if !externalResolvers[resolver] {
			t.Fatalf("external direct call %q was not classified exactly: %v", resolver, externalResolvers)
		}
	}

	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code != "go_call_unresolved" || diagnostic.Path != "model/calls.go" {
			continue
		}
		if diagnostic.ID == "" || callFileDiagnostics[diagnostic.ID] {
			t.Fatalf("unresolved call diagnostic has a missing/duplicate ID: %+v", diagnostic)
		}
		callFileDiagnostics[diagnostic.ID] = true
		if len(diagnostic.Evidence) == 0 || diagnostic.StartLine != diagnostic.Evidence[0].StartLine || diagnostic.StartColumn != diagnostic.Evidence[0].StartColumn {
			t.Fatalf("unresolved call diagnostic lost its primary span: %+v", diagnostic)
		}
	}
	if len(callFileDiagnostics) != 4 {
		t.Fatalf("calls.go unresolved diagnostics = %d, want 4", len(callFileDiagnostics))
	}

	internalTest := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".TestInternal")
	build := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".Build")
	convert := semanticFindGenericInstance(t, result, "symbol", semanticPackagePath+".Convert", []string{
		semanticPackagePath + ".Output", semanticPackagePath + ".Input",
	})
	semanticRequireStrictCall(t, result, build.ID, convert.ID)
	internalCall := semanticRequireStrictCall(t, result, internalTest.ID, build.ID)
	if goSemanticConditionValue(internalCall.Condition, "go.package_variant") != "internal_test" {
		t.Fatalf("internal test direct call lost its variant: %+v", internalCall)
	}
	externalTest := semanticFindNamedNode(t, result, "symbol", "function", semanticExternalTestPath+".TestExternal")
	externalVariantCall := semanticRequireStrictCall(t, result, externalTest.ID, build.ID)
	if goSemanticConditionValue(externalVariantCall.Condition, "go.package_variant") != "external_test" {
		t.Fatalf("external test direct call lost its variant: %+v", externalVariantCall)
	}
}

func TestGoSemanticValueReferencesAreStrictAndDoNotDuplicateCallsOrTypes(t *testing.T) {
	result := semanticScanFixture(t)
	semanticAssertAllStrictValueReferences(t, result)

	build := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".Build")
	outputToInput := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".outputToInput")
	semanticRequireStrictValueReference(t, result, build.ID, outputToInput.ID)

	outputValue := semanticFindNamedNode(t, result, "symbol", "field", semanticPackagePath+".Output.Value")
	semanticRequireStrictValueReference(t, result, outputToInput.ID, outputValue.ID)

	direct := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".DirectCallMatrix")
	externalCall := semanticFindNamedNode(t, result, "symbol", "function", semanticPackagePath+".ExternalCall")
	lines := []int{}
	for _, edge := range result.Edges {
		if edge.Kind != "references" || edge.Source != direct.ID || edge.Target != externalCall.ID {
			continue
		}
		lines = append(lines, semanticSiteByID(t, result, edge.SiteID).Evidence[0].StartLine)
	}
	sort.Ints(lines)
	if !reflect.DeepEqual(lines, []int{41, 43}) {
		t.Fatalf("ExternalCall value references occur on lines %v, want only first-class uses [41 43]", lines)
	}

	externalKind := semanticFindNamedNode(t, result, "symbol", "variable", semanticPackagePath+".ExternalKind")
	externalReference := semanticReferenceAt(t, result, externalKind.ID, "model/calls.go", 65)
	if externalReference.ResolutionStatus != "external" || externalReference.Precision != "exact" {
		t.Fatalf("external value reference lost exact classification: %+v", externalReference)
	}
	target := semanticNodeByID(t, result, externalReference.TargetIDs[0])
	if target.Kind != "external_system" || target.Locator != "go-symbol:reflect.Invalid" {
		t.Fatalf("external constant target is not canonical: %+v", target)
	}
}

func TestGoSemanticValueReferencesSkipConstantsOwnedByArrayTypes(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/array-owner\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "array.go"), `package arrayowner

const Size = 4

type Buffer [Size]byte

func Local() {
	type LocalBuffer [Size]byte
	var _ LocalBuffer
}
`)

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("array type constant degraded semantic completeness: coverage=%+v diagnostics=%+v", result.Coverage, result.Diagnostics)
	}
	if hasDiagnostic(result.Diagnostics, "go_semantic_owner") {
		t.Fatalf("array type constant emitted a spurious owner diagnostic: %+v", result.Diagnostics)
	}
}

func TestGoSemanticValueReferencesSkipUniverseScopeValues(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/predeclared-values\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "values.go"), `package values

const (
	First = iota
	Second
)

func Enabled() bool {
	_ = false
	return true
}
`)

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("universe-scope values degraded semantic completeness: coverage=%+v diagnostics=%+v", result.Coverage, result.Diagnostics)
	}
	if hasDiagnostic(result.Diagnostics, "go_value_reference_unresolved") {
		t.Fatalf("universe-scope values emitted unresolved diagnostics: %+v", result.Diagnostics)
	}
	for _, site := range result.Sites {
		if site.Kind != "value_reference" || len(site.Evidence) == 0 {
			continue
		}
		switch site.Specifier {
		case "true", "false", "iota":
			t.Fatalf("universe-scope value emitted a reference site: %+v", site)
		}
	}
}

func TestGoSemanticValueReferenceKindsMatchLocalTargets(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/reference-kinds\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "kinds.go"), `package referencekinds

func Use(parameter int) int {
	localVariable := parameter
	const localConstant = 1
	return localVariable + localConstant
}
`)

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	semanticFindNamedNode(t, result, "symbol", "function", "example.com/reference-kinds.Use")
	wantKinds := map[string]string{
		"parameter":     "parameter",
		"localVariable": "local_variable",
		"localConstant": "local_constant",
	}
	for displayName, wantKind := range wantKinds {
		var matches []Site
		for _, site := range result.Sites {
			if site.Kind != "value_reference" || len(site.TargetIDs) != 1 {
				continue
			}
			target := semanticNodeByID(t, result, site.TargetIDs[0])
			if target.DisplayName == displayName {
				matches = append(matches, site)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("value reference to %q matches = %d, want 1: matches=%+v sites=%+v", displayName, len(matches), matches, result.Sites)
		}
		site := matches[0]
		gotKind, _ := site.Evidence[0].Properties["object_kind"].(string)
		if gotKind != wantKind {
			t.Fatalf("value reference to %q object_kind = %q, want %q: %+v", displayName, gotKind, wantKind, site)
		}
		target := semanticNodeByID(t, result, site.TargetIDs[0])
		if semanticNodeKind(target) != wantKind {
			t.Fatalf("value reference to %q target kind = %q, want %q: %+v", displayName, semanticNodeKind(target), wantKind, target)
		}
	}
}

func TestGoSemanticValueReferenceAcrossPackages(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/references\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "lib", "lib.go"), "package lib\n\nvar Value = 1\n")
	writeTestFile(t, filepath.Join(root, "app", "app.go"), "package app\n\nimport \"example.com/references/lib\"\n\nfunc Read() int { return lib.Value }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	read := semanticFindNamedNode(t, result, "symbol", "function", "example.com/references/app.Read")
	value := semanticFindNamedNode(t, result, "symbol", "variable", "example.com/references/lib.Value")
	edge := semanticRequireStrictValueReference(t, result, read.ID, value.ID)
	if edge.Evidence[0].Properties["occurrence_kind"] != "qualified_identifier" {
		t.Fatalf("cross-package reference lost qualified occurrence: %+v", edge.Evidence[0])
	}
	semanticAssertAllStrictValueReferences(t, result)
}

func TestGoSemanticValueReferenceAcrossWorkspaceReplacement(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./app\n\t./lib\n)\n")
	writeTestFile(t, filepath.Join(root, "lib", "go.mod"), "module example.com/reference-new\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "lib", "lib.go"), "package reference\n\nvar Value = 1\n")
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/reference-app\n\ngo 1.26.1\n\nrequire example.com/reference-old v0.0.0\nreplace example.com/reference-old => ../lib\n")
	writeTestFile(t, filepath.Join(root, "app", "app.go"), "package app\n\nimport reference \"example.com/reference-old\"\n\nfunc Read() int { return reference.Value }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	read := semanticFindNamedNode(t, result, "symbol", "function", "example.com/reference-app.Read")
	value := semanticFindNamedNode(t, result, "symbol", "variable", "example.com/reference-new.Value")
	edge := semanticRequireStrictValueReference(t, result, read.ID, value.ID)
	if edge.Evidence[0].Properties["resolver_identity"] != "example.com/reference-new.Value" {
		t.Fatalf("replacement value reference did not retain canonical target resolver: %+v", edge.Evidence[0])
	}
}

func TestGoSemanticExternalGenericFunctionValueReference(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/external-reference\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "reference.go"), "package reference\n\nimport \"slices\"\n\nfunc Ref() { clone := slices.Clone[[]int]; _ = clone }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	ref := semanticFindNamedNode(t, result, "symbol", "function", "example.com/external-reference.Ref")
	var externalSites []Site
	for _, site := range result.Sites {
		if site.Kind == "value_reference" && site.Source == ref.ID && site.ResolutionStatus == "external" {
			externalSites = append(externalSites, site)
		}
	}
	if len(externalSites) != 1 {
		t.Fatalf("external generic function value-reference sites = %d, want 1: %+v", len(externalSites), externalSites)
	}
	site := externalSites[0]
	if site.ResolutionStatus != "external" || site.Precision != "exact" || site.Reason != "" {
		t.Fatalf("external generic function reference has invalid classification: %+v", site)
	}
	target := semanticNodeByID(t, result, site.TargetIDs[0])
	if target.Kind != "external_system" || target.Properties["target_kind"] != "generic_instance" ||
		target.Properties["resolver_identity"] != "slices.Clone[[]int,int]" {
		t.Fatalf("external generic function reference target is not canonical: %+v", target)
	}
	semanticAssertAllStrictValueReferences(t, result)
}

func TestGoSemanticUnresolvedValueReferenceUsesUnknownSentinelAndReason(t *testing.T) {
	state := &scannerState{
		workspaceIdentity: "unresolved-value-reference",
		profile:           Profile{ID: "go:test", Language: "go"},
		nodes:             map[string]Node{},
		sites:             map[string]Site{},
		edges:             map[string]Edge{},
	}
	extractor := &goSemanticExtractor{state: state, diagnosticIDs: map[string]bool{}, complete: true}
	context := &goSemanticPackage{
		extractor: extractor,
		parents:   map[ast.Node]ast.Node{},
	}
	identifier := &ast.Ident{Name: "missing"}
	object := types.NewVar(token.NoPos, nil, identifier.Name, types.Typ[types.Int])
	target := context.valueReferenceTarget(identifier, object, nil)
	if target.status != "unresolved" || target.precision != "heuristic" || target.reason != "object_identity_unavailable" {
		t.Fatalf("unresolved value target classification = %+v", target)
	}
	unknown := state.nodes[target.nodeID]
	if unknown.Kind != "unknown_target" || unknown.Properties["language"] != "go" {
		t.Fatalf("unresolved value target is not the Go unknown sentinel: %+v", unknown)
	}
}

func TestGoSemanticDirectCallAcrossPackages(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/calls\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "lib", "lib.go"), "package lib\n\nfunc Run() {}\n")
	writeTestFile(t, filepath.Join(root, "app", "app.go"), "package app\n\nimport \"example.com/calls/lib\"\n\nfunc Caller() { lib.Run() }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	caller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/calls/app.Caller")
	callee := semanticFindNamedNode(t, result, "symbol", "function", "example.com/calls/lib.Run")
	semanticRequireStrictCall(t, result, caller.ID, callee.ID)
	semanticAssertAllStrictCalls(t, result)
}

func TestGoSemanticDirectCallAcrossWorkspaceModules(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./app\n\t./lib\n)\n")
	writeTestFile(t, filepath.Join(root, "lib", "go.mod"), "module example.com/workspace-lib\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "lib", "lib.go"), "package lib\n\nfunc Run() {}\n")
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/workspace-app\n\ngo 1.26.1\n\nrequire example.com/workspace-lib v0.0.0\n")
	writeTestFile(t, filepath.Join(root, "app", "app.go"), "package app\n\nimport \"example.com/workspace-lib\"\n\nfunc Caller() { lib.Run() }\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	caller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/workspace-app.Caller")
	callee := semanticFindNamedNode(t, result, "symbol", "function", "example.com/workspace-lib.Run")
	semanticRequireStrictCall(t, result, caller.ID, callee.ID)
	semanticAssertAllStrictCalls(t, result)
}

func TestGoSemanticDirectCallDoesNotResolveInvisibleSiblingModule(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "shadow", "go.mod"), "module golang.org/x/mod\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "shadow", "module", "module.go"), `package module

func Check(path, version string) error { return nil }

type Version struct {
	Path    string
	Version string
}

func (Version) String() string { return "shadow" }
`)
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), `module example.com/invisible-app

go 1.26.1

require golang.org/x/mod v0.38.0
`)
	writeTestFile(t, filepath.Join(root, "app", "go.sum"), `golang.org/x/mod v0.38.0 h1:MECBjubtXD7yj4HrhIUcywNaGeNVUdfVnxmPajOk4yk=
golang.org/x/mod v0.38.0/go.mod h1:V6Xz0pq8TQ3dGqVQ1FVHuelZpAL0uNhSkk9ogYP3c40=
`)
	writeTestFile(t, filepath.Join(root, "app", "app.go"), `package app

import "golang.org/x/mod/module"

func Caller() string {
	_ = module.Check("example.com/value", "v1.0.0")
	return (module.Version{Path: "example.com/value", Version: "v1.0.0"}).String()
}
`)

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	caller := semanticFindNamedNode(t, result, "symbol", "function", "example.com/invisible-app.Caller")
	shadowCheck := semanticFindNamedNode(t, result, "symbol", "function", "golang.org/x/mod/module.Check")
	shadowString := semanticFindNamedNode(t, result, "symbol", "method", "golang.org/x/mod/module.(Version).String")
	shadowTargets := map[string]bool{shadowCheck.ID: true, shadowString.ID: true}
	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	wantResolvers := map[string]bool{
		"golang.org/x/mod/module.Check":            true,
		"golang.org/x/mod/module.(Version).String": true,
	}
	seenResolvers := map[string]bool{}
	callCount := 0
	for _, edge := range result.Edges {
		if edge.Kind != "calls" || edge.Source != caller.ID {
			continue
		}
		callCount++
		if shadowTargets[edge.Target] {
			t.Fatalf("external dependency call resolved to an invisible sibling module: %+v", edge)
		}
		target := nodes[edge.Target]
		resolver, _ := target.Properties["resolver_identity"].(string)
		if edge.ResolutionStatus != "external" || edge.Precision != "exact" || target.Kind != "external_system" || !wantResolvers[resolver] {
			t.Fatalf("invisible sibling call has invalid external target: edge=%+v target=%+v", edge, target)
		}
		seenResolvers[resolver] = true
	}
	if callCount != 2 || !reflect.DeepEqual(seenResolvers, wantResolvers) {
		t.Fatalf("external calls = %d/%v, want 2/%v", callCount, seenResolvers, wantResolvers)
	}
	semanticAssertAllStrictCalls(t, result)
}

func TestGoSemanticDeclarationPreservesBuildCondition(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/tagged\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "tagged.go"), "//go:build semantic_tag\n\npackage tagged\n\ntype Tagged struct{}\n")
	t.Setenv("DEPGRAPH_PROFILE_CONFIG", `{"go_tags":["semantic_tag"]}`)

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	tagged := semanticFindNamedNode(t, result, "type", "struct", "example.com/tagged.Tagged")
	for _, edge := range result.Edges {
		if edge.Kind != "declares" || edge.Target != tagged.ID || edge.SiteID != "" {
			continue
		}
		if edge.Phase != "semantic" || edge.ResolutionStatus != "resolved" || edge.Precision != "exact" {
			t.Fatalf("tagged declaration lost semantic fields: %+v", edge)
		}
		if !conditionDefines(edge.Condition, "go.build_tag:semantic_tag") {
			t.Fatalf("tagged declaration lost build condition: %+v", edge.Condition)
		}
		semanticAssertEvidence(t, edge.Evidence)
		return
	}
	t.Fatalf("Tagged declaration edge was not emitted with its build condition")
}

func TestGoSemanticImplementsAcrossPackages(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.com/cross\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "contract", "contract.go"), "package contract\n\ntype Runner interface { Run() }\n")
	writeTestFile(t, filepath.Join(root, "service", "service.go"), "package service\n\nimport \"example.com/cross/contract\"\n\ntype Service struct{}\nfunc (Service) Run() {}\nvar _ contract.Runner = Service{}\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	runner := semanticFindNamedNode(t, result, "type", "interface", "example.com/cross/contract.Runner")
	service := semanticFindNamedNode(t, result, "type", "struct", "example.com/cross/service.Service")
	semanticRequireSiteLessRelation(t, result, "implements", service.ID, runner.ID)
}

func TestGoSemanticImplementsAcrossLocalReplacement(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "lib", "go.mod"), "module example.com/implements-new\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "lib", "lib.go"), "package lib\n\ntype Service struct{}\nfunc (Service) Run() {}\n")
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), `module example.com/implements-app

go 1.26.1

require example.com/implements-old v0.0.0
replace example.com/implements-old => ../lib
`)
	writeTestFile(t, filepath.Join(root, "app", "app.go"), `package app

import old "example.com/implements-old"

type Runner interface { Run() }
var _ Runner = old.Service{}
`)

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got := result.Profile.Properties["go_packages_status"]; got != "loaded" {
		t.Fatalf("local replacement typed status = %q, want loaded; diagnostics=%+v", got, result.Diagnostics)
	}
	runner := semanticFindNamedNode(t, result, "type", "interface", "example.com/implements-app.Runner")
	service := semanticFindNamedNode(t, result, "type", "struct", "example.com/implements-new.Service")
	semanticRequireSiteLessRelation(t, result, "implements", service.ID, runner.ID)
}

func TestGoSemanticImplementsAcrossWorkspaceModules(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.26.1\n\nuse (\n\t./api\n\t./service\n\t./shared\n)\n")
	writeTestFile(t, filepath.Join(root, "shared", "go.mod"), "module example.com/shared\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(root, "shared", "shared.go"), "package shared\n\ntype Request struct{}\n")
	writeTestFile(t, filepath.Join(root, "api", "go.mod"), "module example.com/api\n\ngo 1.26.1\n\nrequire example.com/shared v0.0.0\n")
	writeTestFile(t, filepath.Join(root, "api", "api.go"), "package api\n\nimport \"example.com/shared\"\n\ntype Handler interface { Handle(shared.Request) }\n")
	writeTestFile(t, filepath.Join(root, "service", "go.mod"), "module example.com/service\n\ngo 1.26.1\n\nrequire example.com/shared v0.0.0\n")
	writeTestFile(t, filepath.Join(root, "service", "service.go"), "package service\n\nimport \"example.com/shared\"\n\ntype Service struct{}\nfunc (Service) Handle(shared.Request) {}\n")

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got := result.Profile.Properties["go_packages_status"]; got != "loaded" {
		t.Fatalf("workspace typed status = %q, want loaded; diagnostics=%+v", got, result.Diagnostics)
	}
	handler := semanticFindNamedNode(t, result, "type", "interface", "example.com/api.Handler")
	service := semanticFindNamedNode(t, result, "type", "struct", "example.com/service.Service")
	semanticRequireSiteLessRelation(t, result, "implements", service.ID, handler.ID)
}

func TestGoSemanticScanIsDeterministic(t *testing.T) {
	root := semanticFixtureRoot(t)
	first, err := Scan(root)
	if err != nil {
		t.Fatalf("first Scan() error = %v", err)
	}
	second, err := Scan(root)
	if err != nil {
		t.Fatalf("second Scan() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two scans of the same root produced different results")
	}

	var firstEvents bytes.Buffer
	if err := Emit(&firstEvents, "semantic-determinism", first); err != nil {
		t.Fatalf("first Emit() error = %v", err)
	}
	var secondEvents bytes.Buffer
	if err := Emit(&secondEvents, "semantic-determinism", second); err != nil {
		t.Fatalf("second Emit() error = %v", err)
	}
	if !bytes.Equal(firstEvents.Bytes(), secondEvents.Bytes()) {
		t.Fatal("two emissions of the same semantic graph differ")
	}

	copyA := filepath.Join(t.TempDir(), "one", "repository")
	copyB := filepath.Join(t.TempDir(), "two", "other", "repository")
	copyTree(t, root, copyA)
	copyTree(t, root, copyB)
	resultA, err := Scan(copyA)
	if err != nil {
		t.Fatalf("Scan(copy A) error = %v", err)
	}
	resultB, err := Scan(copyB)
	if err != nil {
		t.Fatalf("Scan(copy B) error = %v", err)
	}
	snapshotA := semanticOnlySnapshot(resultA)
	snapshotB := semanticOnlySnapshot(resultB)
	if len(snapshotA.Nodes) == 0 || len(snapshotA.Edges) == 0 || len(snapshotA.Sites) == 0 {
		t.Fatalf("semantic snapshot is empty: nodes=%d edges=%d sites=%d", len(snapshotA.Nodes), len(snapshotA.Edges), len(snapshotA.Sites))
	}
	if !reflect.DeepEqual(snapshotA, snapshotB) {
		t.Fatal("semantic graph changed when the fixture moved to another absolute root")
	}
	encoded, err := json.Marshal(snapshotA)
	if err != nil {
		t.Fatal(err)
	}
	for _, absoluteRoot := range []string{copyA, copyB} {
		if bytes.Contains(encoded, []byte(absoluteRoot)) {
			t.Fatalf("semantic graph leaked absolute root %q", absoluteRoot)
		}
	}
}

func TestGoSemanticPartialTypedFailureIsDiagnosed(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	bad := filepath.Join(root, "bad")
	writeTestFile(t, filepath.Join(good, "go.mod"), "module example.com/good\n\ngo 1.26.1\n")
	writeTestFile(t, filepath.Join(good, "good.go"), "package good\n\ntype Good struct{}\n\nfunc New() Good { return Good{} }\n")
	writeTestFile(t, filepath.Join(bad, "go.mod"), "module example.com/bad\n\ngo 1.26.1\n\nrequire example.invalid/missing v1.2.3\n")
	writeTestFile(t, filepath.Join(bad, "bad.go"), "package bad\n\nimport _ \"example.invalid/missing/pkg\"\n")
	moduleCache := filepath.Join(t.TempDir(), "empty-module-cache")
	if err := os.MkdirAll(moduleCache, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOPATH", filepath.Join(t.TempDir(), "isolated-gopath"))

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got := result.Profile.Properties["go_packages_status"]; got != "partial" {
		t.Fatalf("go_packages_status = %q, want partial; diagnostics=%+v", got, result.Diagnostics)
	}
	if result.Coverage.ProjectCodeExecuted {
		t.Fatal("partial semantic scan reported project code execution")
	}
	if containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("partial typed scan claimed semantic completeness: %+v", result.Coverage)
	}
	if !containsString(result.Coverage.Reasons, semanticParserFallbackCoverage) {
		t.Fatalf("parser fallback reason missing: %+v", result.Coverage)
	}

	goodType := semanticFindNamedNode(t, result, "type", "struct", "example.com/good.Good")
	newFunction := semanticFindNamedNode(t, result, "symbol", "function", "example.com/good.New")
	for _, node := range []Node{goodType, newFunction} {
		if got := semanticStringProperty(t, node, "package_locator"); got != semanticGoodPackageLocator {
			t.Fatalf("good semantic node package locator = %q, want %q: %+v", got, semanticGoodPackageLocator, node)
		}
	}
	semanticRequireStrictTypeUse(t, result, newFunction.ID, goodType.ID)

	for _, node := range result.Nodes {
		if node.Kind != "symbol" && node.Kind != "type" {
			continue
		}
		if strings.Contains(semanticStringProperty(t, node, "package_locator"), "example.com/bad") {
			t.Fatalf("failed module leaked a semantic node: %+v", node)
		}
	}
	assertSiteStatus(t, result.Sites, "side_effect_import", "example.invalid/missing/pkg", "external")
	if !semanticHasDiagnosticAtPath(result.Diagnostics, "go_packages_module_fallback", "bad/go.mod") {
		t.Fatalf("failed module fallback diagnostic missing: %+v", result.Diagnostics)
	}
	if !hasDiagnostic(result.Diagnostics, "go_packages_package_error") &&
		!hasDiagnostic(result.Diagnostics, "go_packages_load_failed") &&
		!hasDiagnostic(result.Diagnostics, "go_packages_typed_incomplete") {
		t.Fatalf("typed failure diagnostic missing: %+v", result.Diagnostics)
	}
}

func TestGoSemanticScopesDuplicateModuleInstances(t *testing.T) {
	root := t.TempDir()
	for _, relativeDir := range []string{"one", "two"} {
		moduleRoot := filepath.Join(root, relativeDir)
		writeTestFile(t, filepath.Join(moduleRoot, "go.mod"), "module example.test/shared\n\ngo 1.26\n")
		writeTestFile(t, filepath.Join(moduleRoot, "shared.go"), `package shared

import "example.test/shared/sub"

type Shared struct{}

func Value() Shared { return Shared{} }

func UseSub(value sub.Token) sub.Token {
	sub.Run()
	return value
}
`)
		writeTestFile(t, filepath.Join(moduleRoot, "sub", "sub.go"), `package sub

type Token struct{}

func Run() Token { return Token{} }
`)
	}

	result, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got := result.Profile.Properties["go_packages_status"]; got != "loaded" {
		t.Fatalf("go_packages_status = %q, want loaded; diagnostics=%+v", got, result.Diagnostics)
	}

	packageIDs := map[string]string{}
	for _, node := range result.Nodes {
		if node.Kind != "module" || node.Locator != "go-package:example.test/shared" {
			continue
		}
		manifest, _ := node.Properties["manifest_path"].(string)
		manifest = strings.TrimSuffix(filepath.ToSlash(manifest), "/go.mod")
		packageIDs[manifest] = node.ID
	}
	if len(packageIDs) != 2 {
		t.Fatalf("duplicate module package nodes = %v, want one and two", packageIDs)
	}

	resolverPackages := map[string]string{
		"example.test/shared.Shared":    "example.test/shared",
		"example.test/shared.Value":     "example.test/shared",
		"example.test/shared.UseSub":    "example.test/shared",
		"example.test/shared/sub.Token": "example.test/shared/sub",
		"example.test/shared/sub.Run":   "example.test/shared/sub",
	}
	allResolvers := []string{
		"example.test/shared.Shared",
		"example.test/shared.Value",
		"example.test/shared.UseSub",
		"example.test/shared/sub.Token",
		"example.test/shared/sub.Run",
	}
	semanticNodes := map[string]map[string]Node{"one": {}, "two": {}}
	for _, node := range result.Nodes {
		if node.Kind != "type" && node.Kind != "symbol" {
			continue
		}
		identity := semanticIdentity(t, node)
		resolver, _ := identity["resolver_identity"].(string)
		packagePath, wanted := resolverPackages[resolver]
		if !wanted {
			continue
		}
		locator, _ := node.Properties["package_locator"].(string)
		for _, relativeDir := range []string{"one", "two"} {
			want := "go:example.test/shared@workspace#" + relativeDir + "#" + packagePath
			if locator == want {
				semanticNodes[relativeDir][resolver] = node
			}
		}
	}
	rootResolvers := []string{
		"example.test/shared.Shared",
		"example.test/shared.Value",
		"example.test/shared.UseSub",
	}
	for _, relativeDir := range []string{"one", "two"} {
		for _, resolver := range allResolvers {
			node, ok := semanticNodes[relativeDir][resolver]
			if !ok {
				t.Fatalf("module %q semantic node %q missing: %+v", relativeDir, resolver, semanticNodes[relativeDir])
			}
			if containsString(rootResolvers, resolver) {
				declared := false
				for _, edge := range result.Edges {
					if edge.Kind == "declares" && edge.Source == packageIDs[relativeDir] && edge.Target == node.ID {
						declared = true
						break
					}
				}
				if !declared {
					t.Fatalf("module %q package %s does not declare semantic node %s", relativeDir, packageIDs[relativeDir], node.ID)
				}
			}
		}
	}
	for _, resolver := range allResolvers {
		if semanticNodes["one"][resolver].ID == semanticNodes["two"][resolver].ID {
			t.Fatalf("duplicate module semantic identity %q collided", resolver)
		}
	}
	for _, relativeDir := range []string{"one", "two"} {
		otherDir := "one"
		if relativeDir == "one" {
			otherDir = "two"
		}
		useSub := semanticNodes[relativeDir]["example.test/shared.UseSub"]
		token := semanticNodes[relativeDir]["example.test/shared/sub.Token"]
		run := semanticNodes[relativeDir]["example.test/shared/sub.Run"]
		otherToken := semanticNodes[otherDir]["example.test/shared/sub.Token"]
		otherRun := semanticNodes[otherDir]["example.test/shared/sub.Run"]
		semanticRequireStrictTypeUse(t, result, useSub.ID, token.ID)
		semanticRequireStrictCall(t, result, useSub.ID, run.ID)
		semanticForbidRelation(t, result, "type_uses", useSub.ID, otherToken.ID)
		semanticForbidRelation(t, result, "calls", useSub.ID, otherRun.ID)
	}
}

func TestGoSemanticIncompleteCoverageHasExplicitReason(t *testing.T) {
	state := scannerState{
		workspaceIdentity:  "semantic-incomplete-test",
		profile:            Profile{ID: "go:test", Language: "go"},
		goPackages:         goPackagesInventory{Status: "loaded"},
		semanticIncomplete: true,
	}
	result := state.result(0)
	if containsString(result.Coverage.Completeness, "semantic-complete") {
		t.Fatalf("incomplete semantic pass claimed completeness: %+v", result.Coverage)
	}
	if !containsString(result.Coverage.Reasons, "go-semantic-incomplete") {
		t.Fatalf("semantic incomplete reason is missing: %+v", result.Coverage)
	}
}

func semanticScanFixture(t *testing.T) Result {
	t.Helper()
	result, err := Scan(semanticFixtureRoot(t))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	return result
}

func semanticFixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", "semantic"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func semanticFindNamedNode(t *testing.T, result Result, nodeKind, semanticKind, resolverIdentity string) Node {
	t.Helper()
	var matches []Node
	for _, node := range result.Nodes {
		if node.Kind != nodeKind || semanticNodeKind(node) != semanticKind {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["resolver_identity"] != resolverIdentity {
			continue
		}
		if nodeKind == "symbol" && identity["identity_kind"] != "named" {
			continue
		}
		matches = append(matches, node)
	}
	if len(matches) != 1 {
		t.Fatalf("named %s/%s %q matches = %d, want 1; semantic nodes:\n%s", nodeKind, semanticKind, resolverIdentity, len(matches), semanticNodeSummary(result))
	}
	return matches[0]
}

func semanticFindLocalNode(t *testing.T, result Result, symbolKind, displayName string) Node {
	t.Helper()
	var matches []Node
	for _, node := range result.Nodes {
		if node.Kind != "symbol" || semanticNodeKind(node) != symbolKind || node.DisplayName != displayName {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["identity_kind"] == "local" {
			matches = append(matches, node)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("local symbol %s %q matches = %d, want 1; semantic nodes:\n%s", symbolKind, displayName, len(matches), semanticNodeSummary(result))
	}
	return matches[0]
}

func semanticFindGenericInstance(t *testing.T, result Result, nodeKind, genericOrigin string, typeArguments []string) Node {
	t.Helper()
	var matches []Node
	for _, node := range result.Nodes {
		if node.Kind != nodeKind {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["generic_origin"] != genericOrigin {
			continue
		}
		if reflect.DeepEqual(semanticStringSlice(identity["type_arguments"]), typeArguments) {
			matches = append(matches, node)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("generic %s instance %q%v matches = %d, want 1; semantic nodes:\n%s", nodeKind, genericOrigin, typeArguments, len(matches), semanticNodeSummary(result))
	}
	return matches[0]
}

func semanticAssertNodeContract(t *testing.T, node Node) (map[string]any, string) {
	t.Helper()
	identity := semanticIdentity(t, node)
	canonical, err := semanticCanonicalJSON(identity)
	if err != nil {
		t.Fatalf("canonicalize node %s identity: %v", node.ID, err)
	}
	if got, want := node.ID, semanticCanonicalValueID(node.Kind, identity); got != want {
		t.Fatalf("node ID = %q, want %q from canonical_identity %s", got, want, canonical)
	}
	if node.Locator == "" || node.DisplayName == "" {
		t.Fatalf("semantic node lacks locator/display_name: %+v", node)
	}
	for _, key := range []string{"language", "package_locator"} {
		property := semanticStringProperty(t, node, key)
		identityValue, ok := identity[key].(string)
		if !ok || identityValue != property {
			t.Fatalf("node %s %s mismatch: property=%q identity=%#v", node.ID, key, property, identity[key])
		}
	}
	if semanticStringProperty(t, node, "language") != "go" {
		t.Fatalf("semantic node language is not go: %+v", node)
	}
	kindKey := node.Kind + "_kind"
	if identity[kindKey] != semanticStringProperty(t, node, kindKey) {
		t.Fatalf("node %s %s mismatch: property=%#v identity=%#v", node.ID, kindKey, node.Properties[kindKey], identity[kindKey])
	}
	if node.Kind == "symbol" {
		identityKind, _ := identity["identity_kind"].(string)
		switch identityKind {
		case "named":
			if resolver, _ := identity["resolver_identity"].(string); resolver == "" {
				t.Fatalf("named symbol has no resolver_identity: %+v", identity)
			}
		case "local", "anonymous", "generated":
			if _, hasEnclosing := identity["enclosing_symbol"]; !hasEnclosing {
				if _, hasGeneratedFrom := identity["generated_from"]; !hasGeneratedFrom {
					t.Fatalf("%s symbol has no enclosing/generated identity: %+v", identityKind, identity)
				}
			}
			if path, _ := identity["relative_path"].(string); path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
				t.Fatalf("%s symbol has invalid relative_path: %+v", identityKind, identity)
			}
			semanticAssertCompleteIdentitySpan(t, identity)
		default:
			t.Fatalf("symbol has invalid identity_kind %#v: %+v", identity["identity_kind"], node)
		}
	}
	return identity, string(canonical)
}

func semanticIdentity(t *testing.T, node Node) map[string]any {
	t.Helper()
	if node.Properties == nil {
		t.Fatalf("semantic node %s has nil properties", node.ID)
	}
	raw, exists := node.Properties["canonical_identity"]
	if !exists {
		t.Fatalf("semantic node %s has no canonical_identity: %+v", node.ID, node)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal canonical_identity for %s: %v", node.ID, err)
	}
	var identity map[string]any
	if err := json.Unmarshal(encoded, &identity); err != nil {
		t.Fatalf("canonical_identity for %s is not an object: %v", node.ID, err)
	}
	if identity == nil {
		t.Fatalf("canonical_identity for %s is null", node.ID)
	}
	return identity
}

func semanticStringProperty(t *testing.T, node Node, key string) string {
	t.Helper()
	value, ok := node.Properties[key].(string)
	if !ok || value == "" {
		t.Fatalf("node %s property %q is not a non-empty string: %#v", node.ID, key, node.Properties[key])
	}
	return value
}

func semanticNodeKind(node Node) string {
	value, _ := node.Properties[node.Kind+"_kind"].(string)
	return value
}

func semanticAssertIdentitySpan(t *testing.T, identity map[string]any, startLine, startColumn, endLine, endColumn int) {
	t.Helper()
	span := semanticIdentitySpan(t, identity)
	want := map[string]int{
		"start_line": startLine, "start_column": startColumn,
		"end_line": endLine, "end_column": endColumn,
	}
	for key, expected := range want {
		if got := semanticInt(span[key]); got != expected {
			t.Fatalf("identity span %s = %d, want %d: %+v", key, got, expected, span)
		}
	}
}

func semanticAssertCompleteIdentitySpan(t *testing.T, identity map[string]any) {
	t.Helper()
	span := semanticIdentitySpan(t, identity)
	for _, key := range []string{"start_line", "start_column", "end_line", "end_column"} {
		if semanticInt(span[key]) <= 0 {
			t.Fatalf("identity has incomplete span %s: %+v", key, identity)
		}
	}
}

func semanticIdentitySpan(t *testing.T, identity map[string]any) map[string]any {
	t.Helper()
	span, ok := identity["span"].(map[string]any)
	if !ok {
		t.Fatalf("identity span is not an object: %+v", identity)
	}
	return span
}

func semanticRequireSiteLessRelation(t *testing.T, result Result, kind, sourceID, targetID string) Edge {
	t.Helper()
	var matches []Edge
	for _, edge := range result.Edges {
		if edge.Kind != kind || edge.Target != targetID || (sourceID != "" && edge.Source != sourceID) {
			continue
		}
		matches = append(matches, edge)
	}
	if len(matches) == 0 {
		t.Fatalf("missing site-less %s edge %q -> %q; semantic edges:\n%s", kind, sourceID, targetID, semanticEdgeSummary(result))
	}
	for _, edge := range matches {
		if edge.SiteID == "" && isAlwaysCondition(edge.Condition) {
			semanticAssertSemanticEdge(t, result, edge, false)
			return edge
		}
	}
	t.Fatalf("missing unconditional site-less %s edge %q -> %q; matches=%+v", kind, sourceID, targetID, matches)
	return Edge{}
}

func semanticRequireConditionalRelation(t *testing.T, result Result, kind, sourceID, targetID, key, value string) Edge {
	t.Helper()
	for _, edge := range result.Edges {
		if edge.Kind != kind || edge.Target != targetID || (sourceID != "" && edge.Source != sourceID) || edge.SiteID != "" {
			continue
		}
		if edge.Condition.Op != "eq" || edge.Condition.Key != key || edge.Condition.Value != value {
			continue
		}
		if !strings.HasPrefix(edge.ID, "edge:sha256:") || edge.Phase != "semantic" || edge.Environment != "any" ||
			edge.ProfileID != result.Profile.ID || edge.ResolutionStatus != "resolved" || edge.Precision != "exact" || edge.Generated {
			t.Fatalf("conditional semantic edge lost contract fields: %+v", edge)
		}
		semanticAssertEvidence(t, edge.Evidence)
		return edge
	}
	t.Fatalf("missing conditional %s edge %q -> %q with %s=%s", kind, sourceID, targetID, key, value)
	return Edge{}
}

func semanticForbidRelation(t *testing.T, result Result, kind, sourceID, targetID string) {
	t.Helper()
	for _, edge := range result.Edges {
		if edge.Kind == kind && edge.Source == sourceID && edge.Target == targetID {
			t.Fatalf("unexpected %s edge %s -> %s: %+v", kind, sourceID, targetID, edge)
		}
	}
}

func semanticUnexpectedSiteRelation(t *testing.T, kind, sourceID, targetID string, matches []Edge) Edge {
	t.Helper()
	t.Fatalf("%s relation %q -> %q unexpectedly has dependency sites: %+v", kind, sourceID, targetID, matches)
	return Edge{}
}

func semanticRequireStrictTypeUse(t *testing.T, result Result, sourceID, targetID string) Edge {
	t.Helper()
	for _, edge := range result.Edges {
		if edge.Kind != "type_uses" || edge.Source != sourceID || edge.Target != targetID {
			continue
		}
		semanticAssertSemanticEdge(t, result, edge, true)
		site := semanticSiteByID(t, result, edge.SiteID)
		if site.Source != sourceID || site.Kind != "type_use" {
			t.Fatalf("type_uses edge points at an invalid site: edge=%+v site=%+v", edge, site)
		}
		if site.Specifier == "" {
			t.Fatalf("type_use site has an empty specifier: %+v", site)
		}
		if !reflect.DeepEqual(site.TargetIDs, []string{targetID}) {
			t.Fatalf("type_use target IDs = %v, want [%s]", site.TargetIDs, targetID)
		}
		if site.ProfileID != result.Profile.ID || site.ResolutionStatus != "resolved" || site.Precision != "exact" || !isAlwaysCondition(site.Condition) {
			t.Fatalf("type_use site lost semantic resolution fields: %+v", site)
		}
		semanticAssertEvidence(t, site.Evidence)
		if !reflect.DeepEqual(edge.Evidence[0], site.Evidence[0]) {
			t.Fatalf("type_uses edge and site primary evidence differ: edge=%+v site=%+v", edge.Evidence[0], site.Evidence[0])
		}
		primary := site.Evidence[0]
		wantSiteID := semanticCanonicalValueID("site", map[string]any{
			"condition":  site.Condition,
			"kind":       site.Kind,
			"path":       primary.Path,
			"profile_id": site.ProfileID,
			"source":     site.Source,
			"span": map[string]any{
				"start_line": primary.StartLine, "start_column": primary.StartColumn,
				"end_line": primary.EndLine, "end_column": primary.EndColumn,
			},
		})
		if site.ID != wantSiteID {
			t.Fatalf("type_use site ID = %q, want %q from primary occurrence", site.ID, wantSiteID)
		}
		wantEdgeID := semanticCanonicalValueID("edge", map[string]any{
			"kind": edge.Kind, "site_id": edge.SiteID, "target": edge.Target,
		})
		if edge.ID != wantEdgeID {
			t.Fatalf("type_uses edge ID = %q, want %q", edge.ID, wantEdgeID)
		}
		return edge
	}
	t.Fatalf("missing strict type_uses edge %s -> %s; semantic edges:\n%s", sourceID, targetID, semanticEdgeSummary(result))
	return Edge{}
}

func semanticAssertAllStrictTypeUses(t *testing.T, result Result) {
	t.Helper()
	nodes := make(map[string]Node, len(result.Nodes))
	sites := make(map[string]Site, len(result.Sites))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	for _, site := range result.Sites {
		sites[site.ID] = site
		if site.Kind != "type_use" {
			continue
		}
		semanticAssertEvidence(t, site.Evidence)
		primary := site.Evidence[0]
		wantID := semanticCanonicalValueID("site", map[string]any{
			"condition": site.Condition, "kind": site.Kind, "path": primary.Path,
			"profile_id": site.ProfileID, "source": site.Source,
			"span": map[string]any{
				"start_line": primary.StartLine, "start_column": primary.StartColumn,
				"end_line": primary.EndLine, "end_column": primary.EndColumn,
			},
		})
		if site.ID != wantID {
			t.Fatalf("type_use site ID = %q, want %q: %+v", site.ID, wantID, site)
		}
		if source := nodes[site.Source]; source.Kind != "symbol" && source.Kind != "type" {
			t.Fatalf("type_use source is not semantic: site=%+v source=%+v", site, source)
		}
		if !sort.StringsAreSorted(site.TargetIDs) || len(site.TargetIDs) == 0 {
			t.Fatalf("type_use targets are not a non-empty sorted set: %+v", site)
		}
		for index := 1; index < len(site.TargetIDs); index++ {
			if site.TargetIDs[index-1] == site.TargetIDs[index] {
				t.Fatalf("type_use targets are not unique: %+v", site)
			}
		}
		for _, targetID := range site.TargetIDs {
			target := nodes[targetID]
			switch site.ResolutionStatus {
			case "resolved", "candidates":
				if target.Kind != "type" {
					t.Fatalf("concrete type_use target is not a type: site=%+v target=%+v", site, target)
				}
			case "external":
				if target.Kind != "external_system" {
					t.Fatalf("external type_use target is not external_system: site=%+v target=%+v", site, target)
				}
			case "unresolved":
				if target.Kind != "unknown_target" || site.Reason == "" {
					t.Fatalf("unresolved type_use lost sentinel/reason: site=%+v target=%+v", site, target)
				}
			default:
				t.Fatalf("type_use has invalid status: %+v", site)
			}
		}
	}
	for _, edge := range result.Edges {
		if edge.Kind != "type_uses" {
			continue
		}
		site, ok := sites[edge.SiteID]
		if !ok || site.Kind != "type_use" {
			t.Fatalf("type_uses edge lacks type_use site: %+v", edge)
		}
		wantID := semanticCanonicalValueID("edge", map[string]any{
			"kind": edge.Kind, "site_id": edge.SiteID, "target": edge.Target,
		})
		if edge.ID != wantID {
			t.Fatalf("type_uses edge ID = %q, want %q", edge.ID, wantID)
		}
		if edge.Phase != "semantic" || edge.Source != site.Source || edge.ProfileID != site.ProfileID ||
			edge.ResolutionStatus != site.ResolutionStatus || edge.Precision != site.Precision ||
			!reflect.DeepEqual(edge.Evidence[0], site.Evidence[0]) {
			t.Fatalf("type_uses edge disagrees with site: edge=%+v site=%+v", edge, site)
		}
	}
}

func semanticRequireStrictValueReference(t *testing.T, result Result, sourceID, targetID string) Edge {
	t.Helper()
	for _, edge := range result.Edges {
		if edge.Kind != "references" || edge.Source != sourceID || edge.Target != targetID {
			continue
		}
		semanticAssertSemanticEdge(t, result, edge, true)
		site := semanticSiteByID(t, result, edge.SiteID)
		if site.Source != sourceID || site.Kind != "value_reference" ||
			!reflect.DeepEqual(site.TargetIDs, []string{targetID}) {
			t.Fatalf("references edge points at an invalid site: edge=%+v site=%+v", edge, site)
		}
		return edge
	}
	t.Fatalf("missing strict references edge %s -> %s; semantic edges:\n%s", sourceID, targetID, semanticEdgeSummary(result))
	return Edge{}
}

func semanticAssertAllStrictValueReferences(t *testing.T, result Result) {
	t.Helper()
	nodes := make(map[string]Node, len(result.Nodes))
	sites := make(map[string]Site, len(result.Sites))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	for _, site := range result.Sites {
		sites[site.ID] = site
		if site.Kind != "value_reference" {
			continue
		}
		semanticAssertEvidence(t, site.Evidence)
		primary := site.Evidence[0]
		wantID := semanticCanonicalValueID("site", map[string]any{
			"condition": site.Condition, "kind": site.Kind, "path": primary.Path,
			"profile_id": site.ProfileID, "source": site.Source,
			"span": map[string]any{
				"start_line": primary.StartLine, "start_column": primary.StartColumn,
				"end_line": primary.EndLine, "end_column": primary.EndColumn,
			},
		})
		if site.ID != wantID {
			t.Fatalf("value_reference site ID = %q, want %q: %+v", site.ID, wantID, site)
		}
		if nodes[site.Source].Kind != "symbol" || len(site.TargetIDs) != 1 || site.Specifier == "" {
			t.Fatalf("value_reference has invalid source/target/specifier: site=%+v source=%+v", site, nodes[site.Source])
		}
		objectKind, _ := primary.Properties["object_kind"].(string)
		occurrenceKind, _ := primary.Properties["occurrence_kind"].(string)
		if objectKind == "" || occurrenceKind == "" {
			t.Fatalf("value_reference evidence lacks occurrence classification: %+v", primary)
		}
		target := nodes[site.TargetIDs[0]]
		switch site.ResolutionStatus {
		case "resolved":
			if target.Kind != "symbol" || site.Precision != "exact" || site.Reason != "" {
				t.Fatalf("resolved value_reference has invalid target/precision/reason: site=%+v target=%+v", site, target)
			}
		case "external":
			if target.Kind != "external_system" || site.Precision != "exact" || site.Reason != "" {
				t.Fatalf("external value_reference has invalid target/precision/reason: site=%+v target=%+v", site, target)
			}
		case "unresolved":
			if target.Kind != "unknown_target" || site.Precision != "heuristic" || site.Reason == "" {
				t.Fatalf("unresolved value_reference lost sentinel/reason: site=%+v target=%+v", site, target)
			}
		default:
			t.Fatalf("value_reference has invalid status: %+v", site)
		}
	}
	for _, edge := range result.Edges {
		if edge.Kind != "references" {
			continue
		}
		site, ok := sites[edge.SiteID]
		if !ok || site.Kind != "value_reference" {
			t.Fatalf("references edge lacks value_reference site: %+v", edge)
		}
		wantID := semanticCanonicalValueID("edge", map[string]any{
			"kind": edge.Kind, "site_id": edge.SiteID, "target": edge.Target,
		})
		if edge.ID != wantID || edge.Source != site.Source || edge.Target != site.TargetIDs[0] ||
			edge.Phase != "semantic" || edge.Environment != "any" || edge.ProfileID != site.ProfileID ||
			edge.ResolutionStatus != site.ResolutionStatus || edge.Precision != site.Precision ||
			!reflect.DeepEqual(edge.Condition, site.Condition) || !reflect.DeepEqual(edge.Evidence, site.Evidence) {
			t.Fatalf("references edge disagrees with its site or canonical identity: edge=%+v site=%+v want_id=%s", edge, site, wantID)
		}
	}
}

func semanticReferenceAt(t *testing.T, result Result, sourceID, path string, line int) Site {
	t.Helper()
	var matches []Site
	for _, site := range result.Sites {
		if site.Kind == "value_reference" && site.Source == sourceID && len(site.Evidence) > 0 &&
			site.Evidence[0].Path == path && site.Evidence[0].StartLine == line {
			matches = append(matches, site)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("value_reference at %s:%d from %s matches = %d, want 1: %+v", path, line, sourceID, len(matches), matches)
	}
	return matches[0]
}

func semanticRequireStrictCall(t *testing.T, result Result, sourceID, targetID string) Edge {
	t.Helper()
	for _, edge := range result.Edges {
		if edge.Kind == "calls" && edge.Source == sourceID && edge.Target == targetID {
			return edge
		}
	}
	t.Fatalf("missing calls edge %s -> %s; semantic edges:\n%s", sourceID, targetID, semanticEdgeSummary(result))
	return Edge{}
}

func semanticAssertAllStrictCalls(t *testing.T, result Result) {
	t.Helper()
	nodes := make(map[string]Node, len(result.Nodes))
	sites := make(map[string]Site, len(result.Sites))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	for _, site := range result.Sites {
		sites[site.ID] = site
		if site.Kind != "call" {
			continue
		}
		if nodes[site.Source].Kind != "symbol" {
			t.Fatalf("call site source is not a symbol: site=%+v source=%+v", site, nodes[site.Source])
		}
		if len(site.TargetIDs) == 0 || !sort.StringsAreSorted(site.TargetIDs) {
			t.Fatalf("call target IDs are not a non-empty sorted set: %+v", site)
		}
		for index := 1; index < len(site.TargetIDs); index++ {
			if site.TargetIDs[index-1] == site.TargetIDs[index] {
				t.Fatalf("call target IDs are not unique: %+v", site)
			}
		}
		semanticAssertEvidence(t, site.Evidence)
		primary := site.Evidence[0]
		if dispatch, _ := primary.Properties["dispatch"].(string); dispatch == "" {
			t.Fatalf("direct call evidence lacks dispatch classification: %+v", primary)
		}
		wantSiteID := semanticCanonicalValueID("site", map[string]any{
			"condition": site.Condition, "kind": site.Kind, "path": primary.Path,
			"profile_id": site.ProfileID, "source": site.Source,
			"span": map[string]any{
				"start_line": primary.StartLine, "start_column": primary.StartColumn,
				"end_line": primary.EndLine, "end_column": primary.EndColumn,
			},
		})
		if site.ID != wantSiteID {
			t.Fatalf("call site ID = %q, want %q: %+v", site.ID, wantSiteID, site)
		}
		switch site.ResolutionStatus {
		case "resolved":
			if len(site.TargetIDs) != 1 || site.Precision != "exact" || nodes[site.TargetIDs[0]].Kind != "symbol" || site.Reason != "" {
				t.Fatalf("resolved call has invalid precision/target/reason: site=%+v target=%+v", site, nodes[site.TargetIDs[0]])
			}
		case "external":
			if len(site.TargetIDs) != 1 || site.Precision != "exact" || nodes[site.TargetIDs[0]].Kind != "external_system" || site.Reason != "" {
				t.Fatalf("external call has invalid precision/target/reason: site=%+v target=%+v", site, nodes[site.TargetIDs[0]])
			}
		case "unresolved":
			if len(site.TargetIDs) != 1 || site.Precision != "heuristic" || nodes[site.TargetIDs[0]].Kind != "unknown_target" || site.Reason == "" {
				t.Fatalf("unresolved call lost sentinel/reason: site=%+v target=%+v", site, nodes[site.TargetIDs[0]])
			}
		case "candidates":
			algorithm, _ := primary.Properties["algorithm"].(string)
			if site.Precision != "overapprox" || site.Reason != "" || primary.Extractor != "go-ssa" || algorithm == "" {
				t.Fatalf("candidate call lost SSA provenance: %+v", site)
			}
			for _, targetID := range site.TargetIDs {
				if nodes[targetID].Kind != "symbol" {
					t.Fatalf("candidate call target is not a symbol: site=%+v target=%+v", site, nodes[targetID])
				}
			}
		default:
			t.Fatalf("call has invalid resolution status: %+v", site)
		}
	}

	edgesBySite := map[string]map[string]bool{}
	seenEdges := map[string]bool{}
	for _, edge := range result.Edges {
		if edge.Kind != "calls" && edge.Kind != "may_call" {
			continue
		}
		if seenEdges[edge.ID] {
			t.Fatalf("duplicate call edge ID: %s", edge.ID)
		}
		seenEdges[edge.ID] = true
		site, ok := sites[edge.SiteID]
		if !ok || site.Kind != "call" {
			t.Fatalf("calls edge lacks call site: %+v", edge)
		}
		expectedKind := "calls"
		if site.ResolutionStatus == "candidates" {
			expectedKind = "may_call"
		}
		if edge.Kind != expectedKind {
			t.Fatalf("call edge kind = %q, want %q: edge=%+v site=%+v", edge.Kind, expectedKind, edge, site)
		}
		if edgesBySite[edge.SiteID] == nil {
			edgesBySite[edge.SiteID] = map[string]bool{}
		}
		if edgesBySite[edge.SiteID][edge.Target] {
			t.Fatalf("duplicate call edge target for site: %+v", edge)
		}
		edgesBySite[edge.SiteID][edge.Target] = true
		if !containsString(site.TargetIDs, edge.Target) || edge.Source != site.Source || edge.ProfileID != site.ProfileID ||
			edge.ResolutionStatus != site.ResolutionStatus || edge.Precision != site.Precision ||
			!reflect.DeepEqual(edge.Condition, site.Condition) || !reflect.DeepEqual(edge.Evidence[0], site.Evidence[0]) {
			t.Fatalf("calls edge disagrees with its site: edge=%+v site=%+v", edge, site)
		}
		if edge.Phase != "semantic" || edge.Environment != "any" {
			t.Fatalf("calls edge lost semantic phase/environment: %+v", edge)
		}
		wantEdgeID := semanticCanonicalValueID("edge", map[string]any{
			"kind": edge.Kind, "site_id": edge.SiteID, "target": edge.Target,
		})
		if edge.ID != wantEdgeID {
			t.Fatalf("calls edge ID = %q, want %q", edge.ID, wantEdgeID)
		}
	}
	for _, site := range sites {
		if site.Kind != "call" {
			continue
		}
		if len(edgesBySite[site.ID]) != len(site.TargetIDs) {
			t.Fatalf("call site %s has %d edges, want %d", site.ID, len(edgesBySite[site.ID]), len(site.TargetIDs))
		}
		for _, targetID := range site.TargetIDs {
			if !edgesBySite[site.ID][targetID] {
				t.Fatalf("call site %s lacks edge to %s", site.ID, targetID)
			}
		}
	}
}

func semanticRequireInitializerTypeUse(t *testing.T, result Result, targetID string) {
	t.Helper()
	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}
	for _, edge := range result.Edges {
		if edge.Kind != "type_uses" || edge.Target != targetID {
			continue
		}
		if source := nodes[edge.Source]; source.Kind == "symbol" && semanticNodeKind(source) == "package_initializer" {
			semanticAssertSemanticEdge(t, result, edge, true)
			return
		}
	}
	t.Fatalf("package initializer has no strict type_uses edge to %s", targetID)
}

func semanticRequirePackageInitializers(t *testing.T, result Result, want int) {
	t.Helper()
	count := 0
	for _, node := range result.Nodes {
		if node.Kind == "symbol" && semanticNodeKind(node) == "package_initializer" {
			semanticAssertNodeContract(t, node)
			count++
		}
	}
	if count != want {
		t.Fatalf("package initializer nodes = %d, want %d", count, want)
	}
}

func semanticRequireAnonymousMembersNotNamed(t *testing.T, result Result, names ...string) {
	t.Helper()
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	for _, node := range result.Nodes {
		if node.Kind != "symbol" || !wanted[node.DisplayName] {
			continue
		}
		if identity := semanticIdentity(t, node); identity["identity_kind"] == "named" {
			t.Fatalf("anonymous member %q was emitted as a named symbol: %+v", node.DisplayName, node)
		}
	}
}

func semanticRequireDistinctScopedTypeArguments(t *testing.T, result Result, genericOrigin string, want int) {
	t.Helper()
	arguments := map[string]bool{}
	for _, node := range result.Nodes {
		if node.Kind != "symbol" {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["generic_origin"] != genericOrigin {
			continue
		}
		values := semanticStringSlice(identity["type_arguments"])
		if len(values) == 0 || !strings.Contains(values[0], "GenericScope") {
			continue
		}
		arguments[strings.Join(values, "\x00")] = true
	}
	if len(arguments) != want {
		t.Fatalf("scoped generic type argument identities = %d, want %d: %v", len(arguments), want, arguments)
	}
}

func semanticRequireGenericInstanceCount(t *testing.T, result Result, genericOrigin string, want int) {
	t.Helper()
	count := 0
	for _, node := range result.Nodes {
		if node.Kind != "type" {
			continue
		}
		identity := semanticIdentity(t, node)
		if identity["generic_origin"] == genericOrigin {
			count++
		}
	}
	if count != want {
		t.Fatalf("generic instances for %q = %d, want %d", genericOrigin, count, want)
	}
}

func semanticRequireScopedGenericImplements(t *testing.T, result Result, concreteOrigin, contractOrigin string, want int) {
	t.Helper()
	concretes := map[string]string{}
	contracts := map[string]string{}
	for _, node := range result.Nodes {
		if node.Kind != "type" {
			continue
		}
		identity := semanticIdentity(t, node)
		arguments := semanticStringSlice(identity["type_arguments"])
		if len(arguments) != 1 {
			continue
		}
		if !strings.Contains(arguments[0], ".ScopedF") && !strings.Contains(arguments[0], ".ScopedG") {
			continue
		}
		switch identity["generic_origin"] {
		case concreteOrigin:
			concretes[node.ID] = arguments[0]
		case contractOrigin:
			contracts[node.ID] = arguments[0]
		}
	}
	if len(concretes) != want || len(contracts) != want {
		t.Fatalf("scoped generic instances = concrete:%d contract:%d, want %d each", len(concretes), len(contracts), want)
	}
	relations := 0
	for _, edge := range result.Edges {
		concreteArgument, concreteOK := concretes[edge.Source]
		contractArgument, contractOK := contracts[edge.Target]
		if edge.Kind != "implements" || !concreteOK || !contractOK {
			continue
		}
		if concreteArgument != contractArgument {
			t.Fatalf("cross-scope generic implements edge: %+v; concrete arg %q, contract arg %q", edge, concreteArgument, contractArgument)
		}
		relations++
	}
	if relations != want {
		t.Fatalf("scoped generic implements relations = %d, want %d", relations, want)
	}
}

func semanticAssertSemanticEdge(t *testing.T, result Result, edge Edge, requireSite bool) {
	t.Helper()
	if !strings.HasPrefix(edge.ID, "edge:sha256:") {
		t.Fatalf("semantic edge has invalid ID: %+v", edge)
	}
	if edge.Phase != "semantic" || edge.Environment != "any" || edge.ProfileID != result.Profile.ID {
		t.Fatalf("semantic edge lost phase/environment/profile: %+v", edge)
	}
	if edge.ResolutionStatus != "resolved" || edge.Precision != "exact" || edge.Generated || !isAlwaysCondition(edge.Condition) {
		t.Fatalf("semantic edge lost resolution/condition fields: %+v", edge)
	}
	if requireSite != (edge.SiteID != "") {
		t.Fatalf("semantic edge site presence = %t, want %t: %+v", edge.SiteID != "", requireSite, edge)
	}
	semanticAssertEvidence(t, edge.Evidence)
}

func semanticAssertEvidence(t *testing.T, evidence []Evidence) {
	t.Helper()
	if len(evidence) == 0 {
		t.Fatal("semantic relation has no evidence")
	}
	primary := evidence[0]
	if primary.Kind != "semantic" ||
		(primary.Extractor != semanticEvidenceExtractor && primary.Extractor != "go-ssa") ||
		primary.ExtractorVersion != AdapterVersion {
		t.Fatalf("semantic evidence has invalid extractor identity: %+v", primary)
	}
	if primary.Path == "" || filepath.IsAbs(primary.Path) || strings.Contains(primary.Path, "\\") {
		t.Fatalf("semantic evidence path is not normalized relative path: %+v", primary)
	}
	if primary.StartLine <= 0 || primary.StartColumn <= 0 || primary.EndLine <= 0 || primary.EndColumn <= 0 ||
		primary.EndLine < primary.StartLine || (primary.EndLine == primary.StartLine && primary.EndColumn < primary.StartColumn) {
		t.Fatalf("semantic evidence has an incomplete span: %+v", primary)
	}
}

func semanticSiteByID(t *testing.T, result Result, siteID string) Site {
	t.Helper()
	for _, site := range result.Sites {
		if site.ID == siteID {
			return site
		}
	}
	t.Fatalf("site %q was not emitted", siteID)
	return Site{}
}

func semanticNodeByID(t *testing.T, result Result, nodeID string) Node {
	t.Helper()
	for _, node := range result.Nodes {
		if node.ID == nodeID {
			return node
		}
	}
	t.Fatalf("node %q was not emitted", nodeID)
	return Node{}
}

func semanticAssertCoverageLedger(t *testing.T, result Result) {
	t.Helper()
	classified := result.Coverage.Resolved + result.Coverage.Candidates + result.Coverage.External + result.Coverage.Unresolved
	if classified != result.Coverage.DependencySites || classified != len(result.Sites) {
		t.Fatalf("coverage site ledger mismatch: coverage=%+v sites=%d", result.Coverage, len(result.Sites))
	}
	for _, completion := range result.Files {
		if completion.DiscoveredSites != completion.EmittedSites+completion.SkippedSites {
			t.Fatalf("file completion is not conserved: %+v", completion)
		}
	}
}

func semanticFileCompletion(t *testing.T, result Result, path string) FileCompletion {
	t.Helper()
	var matches []FileCompletion
	for _, completion := range result.Files {
		if completion.Path == path {
			matches = append(matches, completion)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("file completion %q matches = %d, want 1: %+v", path, len(matches), matches)
	}
	return matches[0]
}

func semanticHasDiagnosticAtPath(diagnostics []Diagnostic, code, path string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && diagnostic.Path == path {
			return true
		}
	}
	return false
}

type semanticGraphSnapshot struct {
	Nodes []Node
	Sites []Site
	Edges []Edge
}

func semanticOnlySnapshot(result Result) semanticGraphSnapshot {
	snapshot := semanticGraphSnapshot{}
	for _, node := range result.Nodes {
		if node.Kind == "symbol" || node.Kind == "type" {
			snapshot.Nodes = append(snapshot.Nodes, node)
		}
	}
	for _, site := range result.Sites {
		if len(site.Evidence) > 0 && site.Evidence[0].Kind == "semantic" {
			snapshot.Sites = append(snapshot.Sites, site)
		}
	}
	for _, edge := range result.Edges {
		if edge.Phase == "semantic" {
			snapshot.Edges = append(snapshot.Edges, edge)
		}
	}
	return snapshot
}

func semanticCanonicalValueID(namespace string, value any) string {
	canonical, err := semanticCanonicalJSON(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(canonical)
	return fmt.Sprintf("%s:sha256:%x", namespace, digest)
}

func semanticCanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

func semanticStringSlice(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil
			}
			result = append(result, text)
		}
		return result
	default:
		return nil
	}
}

func semanticInt(value any) int {
	switch value := value.(type) {
	case int:
		return value
	case float64:
		return int(value)
	case json.Number:
		parsed, _ := value.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func semanticNodeSummary(result Result) string {
	var lines []string
	for _, node := range result.Nodes {
		if node.Kind != "symbol" && node.Kind != "type" {
			continue
		}
		identity, _ := json.Marshal(node.Properties["canonical_identity"])
		lines = append(lines, fmt.Sprintf("%s %s %s %s", node.Kind, semanticNodeKind(node), node.DisplayName, identity))
	}
	return strings.Join(lines, "\n")
}

func semanticEdgeSummary(result Result) string {
	var lines []string
	for _, edge := range result.Edges {
		if edge.Phase == "semantic" {
			lines = append(lines, fmt.Sprintf("%s %s -> %s site=%s", edge.Kind, edge.Source, edge.Target, edge.SiteID))
		}
	}
	return strings.Join(lines, "\n")
}
