// Package issue437golden contains the stable projection used by the Issue 437
// worker golden tests. It deliberately normalizes only profile/toolchain/host
// axes; graph identity and payload drift remains visible to the tests.
package issue437golden

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// NormalizeNDJSON parses a safe worker stream and returns a deterministic
// projection suitable for comparing output captured on different hosts. The
// projection retains every node property, site/evidence field, edge (including
// structural contains/declares edges), file completion, and completion
// coverage. Semantic collections are sorted by logical identity so that the
// projection does not depend on Go map/file-system iteration order. Sequence
// numbers are reassigned after that canonical ordering.
func NormalizeNDJSON(data []byte) ([]map[string]any, error) {
	events, err := eventsFromNDJSON(data)
	if err != nil {
		return nil, err
	}
	maps, err := buildEventMaps(events)
	if err != nil {
		return nil, err
	}
	ordered, err := orderEvents(events, maps)
	if err != nil {
		return nil, err
	}
	for index, event := range ordered {
		eventName, _ := event["event"].(string)
		normalizeValue(event, eventName, false, false)
		// The producer's sequence is a transport ordering detail. It must be
		// normalized together with the host-independent event ordering.
		event["seq"] = float64(index + 1)
		switch eventName {
		case "node_upsert":
			node, err := objectField(event, "node")
			if err != nil {
				return nil, err
			}
			rawID, err := stringField(node, "id")
			if err != nil {
				return nil, err
			}
			node["id"], err = mappedID(maps.nodeIDs, rawID, "node")
			if err != nil {
				return nil, err
			}
		case "dependency_site":
			site, err := objectField(event, "site")
			if err != nil {
				return nil, err
			}
			rawID, err := stringField(site, "id")
			if err != nil {
				return nil, err
			}
			site["id"], err = mappedID(maps.siteIDs, rawID, "site")
			if err != nil {
				return nil, err
			}
			if err := normalizeReference(site, "source", maps.nodeIDs); err != nil {
				return nil, err
			}
			if err := normalizeStringSlice(site, "target_ids", maps.nodeIDs, "site target"); err != nil {
				return nil, err
			}
		case "edge_upsert":
			edge, err := objectField(event, "edge")
			if err != nil {
				return nil, err
			}
			rawID, err := stringField(edge, "id")
			if err != nil {
				return nil, err
			}
			edge["id"], err = mappedID(maps.edgeIDs, rawID, "edge")
			if err != nil {
				return nil, err
			}
			if err := normalizeReference(edge, "source", maps.nodeIDs); err != nil {
				return nil, err
			}
			if err := normalizeReference(edge, "target", maps.nodeIDs); err != nil {
				return nil, err
			}
			if siteID, ok := edge["site_id"].(string); ok && siteID != "" {
				edge["site_id"], err = mappedID(maps.siteIDs, siteID, "edge site")
				if err != nil {
					return nil, err
				}
			}
		case "diagnostic":
			diagnostic, err := objectField(event, "diagnostic")
			if err != nil {
				return nil, err
			}
			normalized, err := normalizeDiagnostic(diagnostic, maps, true)
			if err != nil {
				return nil, err
			}
			event["diagnostic"] = normalized
		}
	}
	return ordered, nil
}

type eventMaps struct {
	scanID             string
	declaredProfileIDs map[string]struct{}
	nodeIDs            map[string]string
	siteIDs            map[string]string
	edgeIDs            map[string]string
	diagnosticIDs      map[string]string
}

func eventsFromNDJSON(data []byte) ([]map[string]any, error) {
	events := []map[string]any{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode Go golden event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Go golden events: %w", err)
	}
	return events, nil
}

func buildEventMaps(events []map[string]any) (eventMaps, error) {
	maps := eventMaps{
		declaredProfileIDs: map[string]struct{}{},
		nodeIDs:            map[string]string{},
		siteIDs:            map[string]string{},
		edgeIDs:            map[string]string{},
		diagnosticIDs:      map[string]string{},
	}
	if err := validateStreamReferences(events, &maps); err != nil {
		return eventMaps{}, err
	}
	for _, event := range events {
		if event["event"] != "node_upsert" {
			continue
		}
		node, err := objectField(event, "node")
		if err != nil {
			return eventMaps{}, err
		}
		rawID, err := stringField(node, "id")
		if err != nil {
			return eventMaps{}, err
		}
		kind, err := stringField(node, "kind")
		if err != nil {
			return eventMaps{}, err
		}
		logicalID, err := nodeLogicalID(node)
		if err != nil {
			return eventMaps{}, err
		}
		// The workspace identity is not profile-scoped, so retaining its raw
		// ID makes a real workspace identity drift fail the comparison.
		normalizedID := rawID
		if profileScopedNodeKind(kind) {
			normalizedID = "profile-node:" + logicalID
		}
		if previous, duplicate := maps.nodeIDs[rawID]; duplicate && previous != normalizedID {
			return eventMaps{}, fmt.Errorf("Go golden node ID %q maps to both %q and %q", rawID, previous, normalizedID)
		}
		for existingRaw, existingNormalized := range maps.nodeIDs {
			if existingRaw != rawID && existingNormalized == normalizedID {
				return eventMaps{}, fmt.Errorf("Go golden logical node %q has multiple IDs %q and %q", normalizedID, existingRaw, rawID)
			}
		}
		maps.nodeIDs[rawID] = normalizedID
	}
	for _, event := range events {
		if event["event"] != "dependency_site" {
			continue
		}
		site, err := objectField(event, "site")
		if err != nil {
			return eventMaps{}, err
		}
		rawID, err := stringField(site, "id")
		if err != nil {
			return eventMaps{}, err
		}
		canonical, err := canonicalSite(site, maps.nodeIDs)
		if err != nil {
			return eventMaps{}, err
		}
		normalizedID := "site:" + canonical
		if previous, duplicate := maps.siteIDs[rawID]; duplicate && previous != normalizedID {
			return eventMaps{}, fmt.Errorf("Go golden site ID %q maps to both %q and %q", rawID, previous, normalizedID)
		}
		for existingRaw, existingNormalized := range maps.siteIDs {
			if existingRaw != rawID && existingNormalized == normalizedID {
				return eventMaps{}, fmt.Errorf("Go golden logical site %q has multiple IDs %q and %q", normalizedID, existingRaw, rawID)
			}
		}
		maps.siteIDs[rawID] = normalizedID
	}
	for _, event := range events {
		if event["event"] != "edge_upsert" {
			continue
		}
		edge, err := objectField(event, "edge")
		if err != nil {
			return eventMaps{}, err
		}
		rawID, err := stringField(edge, "id")
		if err != nil {
			return eventMaps{}, err
		}
		canonical, err := canonicalEdge(edge, maps.nodeIDs, maps.siteIDs)
		if err != nil {
			return eventMaps{}, err
		}
		normalizedID := "edge:" + canonical
		if previous, duplicate := maps.edgeIDs[rawID]; duplicate && previous != normalizedID {
			return eventMaps{}, fmt.Errorf("Go golden edge ID %q maps to both %q and %q", rawID, previous, normalizedID)
		}
		for existingRaw, existingNormalized := range maps.edgeIDs {
			if existingRaw != rawID && existingNormalized == normalizedID {
				return eventMaps{}, fmt.Errorf("Go golden logical edge %q has multiple IDs %q and %q", normalizedID, existingRaw, rawID)
			}
		}
		maps.edgeIDs[rawID] = normalizedID
	}
	for _, event := range events {
		if event["event"] != "diagnostic" {
			continue
		}
		diagnostic, err := objectField(event, "diagnostic")
		if err != nil {
			return eventMaps{}, err
		}
		rawID, err := stringField(diagnostic, "id")
		if err != nil {
			return eventMaps{}, err
		}
		if rawID == "" {
			return eventMaps{}, fmt.Errorf("Go golden diagnostic has empty id")
		}
		canonical, err := canonicalDiagnostic(diagnostic, maps)
		if err != nil {
			return eventMaps{}, err
		}
		normalizedID := "diagnostic:" + canonical
		if previous, duplicate := maps.diagnosticIDs[rawID]; duplicate && previous != normalizedID {
			return eventMaps{}, fmt.Errorf("Go golden diagnostic ID %q maps to both %q and %q", rawID, previous, normalizedID)
		}
		for existingRaw, existingNormalized := range maps.diagnosticIDs {
			if existingRaw != rawID && existingNormalized == normalizedID {
				return eventMaps{}, fmt.Errorf("Go golden logical diagnostic %q has multiple IDs %q and %q", normalizedID, existingRaw, rawID)
			}
		}
		maps.diagnosticIDs[rawID] = normalizedID
	}
	return maps, nil
}

// validateStreamReferences runs before any normalization. Replacing an ID
// before checking it would let an unknown or cross-profile reference become a
// plausible placeholder and make a malformed stream compare equal.
func validateStreamReferences(events []map[string]any, maps *eventMaps) error {
	for index, event := range events {
		rawID, ok := event["scan_id"]
		if !ok {
			return fmt.Errorf("Go golden event %d is missing scan_id", index)
		}
		scanID, ok := rawID.(string)
		if !ok || scanID == "" {
			return fmt.Errorf("Go golden event %d has invalid scan_id: %#v", index, rawID)
		}
		if maps.scanID == "" {
			maps.scanID = scanID
		} else if maps.scanID != scanID {
			return fmt.Errorf("Go golden stream mixes scan_id %q and %q", maps.scanID, scanID)
		}
	}
	if maps.scanID == "" {
		return fmt.Errorf("Go golden stream is empty")
	}

	for index, event := range events {
		if event["event"] != "profile_declared" {
			continue
		}
		profile, err := objectField(event, "profile")
		if err != nil {
			return fmt.Errorf("profile_declared event %d: %w", index, err)
		}
		profileID, err := stringField(profile, "id")
		if err != nil {
			return fmt.Errorf("profile_declared event %d: %w", index, err)
		}
		if profileID == "" {
			return fmt.Errorf("profile_declared event %d has empty profile.id", index)
		}
		if _, duplicate := maps.declaredProfileIDs[profileID]; duplicate {
			return fmt.Errorf("Go golden stream declares profile %q more than once", profileID)
		}
		maps.declaredProfileIDs[profileID] = struct{}{}
	}

	startedProfileIDs := map[string]struct{}{}
	startedCount := 0
	for index, event := range events {
		if event["event"] == "scan_started" {
			startedCount++
			values, ok := event["profile_ids"].([]any)
			if !ok {
				return fmt.Errorf("scan_started event %d profile_ids is not an array: %#v", index, event["profile_ids"])
			}
			for _, value := range values {
				profileID, ok := value.(string)
				if !ok || profileID == "" {
					return fmt.Errorf("scan_started event %d has invalid profile_ids value: %#v", index, value)
				}
				if _, duplicate := startedProfileIDs[profileID]; duplicate {
					return fmt.Errorf("scan_started event %d repeats profile_id %q", index, profileID)
				}
				startedProfileIDs[profileID] = struct{}{}
			}
		}
	}
	if startedCount > 1 {
		return fmt.Errorf("Go golden stream has %d scan_started events", startedCount)
	}
	if startedCount == 1 {
		for profileID := range startedProfileIDs {
			if _, declared := maps.declaredProfileIDs[profileID]; !declared {
				return fmt.Errorf("scan_started references undeclared profile %q", profileID)
			}
		}
		for profileID := range maps.declaredProfileIDs {
			if _, started := startedProfileIDs[profileID]; !started {
				return fmt.Errorf("profile_declared profile %q is absent from scan_started.profile_ids", profileID)
			}
		}
	}

	for index, event := range events {
		if err := validateReferenceValue(event, maps, fmt.Sprintf("event %d", index)); err != nil {
			return err
		}
	}
	return nil
}

func validateReferenceValue(value any, maps *eventMaps, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			fieldPath := path + "." + key
			switch key {
			case "scan_id":
				scanID, ok := child.(string)
				if !ok || scanID != maps.scanID {
					return fmt.Errorf("Go golden %s references scan_id %#v, want %q", fieldPath, child, maps.scanID)
				}
			case "profile_id":
				profileID, ok := child.(string)
				if !ok {
					return fmt.Errorf("Go golden %s is not a string: %#v", fieldPath, child)
				}
				if _, declared := maps.declaredProfileIDs[profileID]; !declared {
					return fmt.Errorf("Go golden %s references undeclared profile %q", fieldPath, profileID)
				}
			case "profile_ids":
				values, ok := child.([]any)
				if !ok {
					return fmt.Errorf("Go golden %s is not an array: %#v", fieldPath, child)
				}
				for itemIndex, item := range values {
					profileID, ok := item.(string)
					if !ok {
						return fmt.Errorf("Go golden %s[%d] is not a string: %#v", fieldPath, itemIndex, item)
					}
					if _, declared := maps.declaredProfileIDs[profileID]; !declared {
						return fmt.Errorf("Go golden %s[%d] references undeclared profile %q", fieldPath, itemIndex, profileID)
					}
				}
			default:
				if err := validateReferenceValue(child, maps, fieldPath); err != nil {
					return err
				}
			}
		}
	case []any:
		for index, child := range typed {
			if err := validateReferenceValue(child, maps, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func orderEvents(events []map[string]any, maps eventMaps) ([]map[string]any, error) {
	type sortableEvent struct {
		event map[string]any
		key   string
		index int
	}
	items := make([]sortableEvent, 0, len(events))
	for index, event := range events {
		key, err := eventOrderingKey(event, maps)
		if err != nil {
			return nil, err
		}
		items = append(items, sortableEvent{event: event, key: key, index: index})
	}
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].key != items[right].key {
			return items[left].key < items[right].key
		}
		return items[left].index < items[right].index
	})
	ordered := make([]map[string]any, len(items))
	for index, item := range items {
		ordered[index] = item.event
	}
	return ordered, nil
}

func eventOrderingKey(event map[string]any, maps eventMaps) (string, error) {
	eventName, _ := event["event"].(string)
	payload, err := cloneObject(event)
	if err != nil {
		return "", err
	}
	delete(payload, "seq")
	normalizeValue(payload, eventName, false, false)
	var logical string
	switch eventName {
	case "node_upsert":
		node, err := objectField(event, "node")
		if err != nil {
			return "", err
		}
		logical, err = nodeLogicalID(node)
		if err != nil {
			return "", err
		}
	case "dependency_site":
		site, err := objectField(event, "site")
		if err != nil {
			return "", err
		}
		logical, err = canonicalSite(site, maps.nodeIDs)
		if err != nil {
			return "", err
		}
	case "edge_upsert":
		edge, err := objectField(event, "edge")
		if err != nil {
			return "", err
		}
		logical, err = canonicalEdge(edge, maps.nodeIDs, maps.siteIDs)
		if err != nil {
			return "", err
		}
	case "diagnostic":
		diagnostic, err := objectField(event, "diagnostic")
		if err != nil {
			return "", err
		}
		logical, err = canonicalDiagnostic(diagnostic, maps)
		if err != nil {
			return "", err
		}
		normalized, err := normalizeDiagnostic(diagnostic, maps, true)
		if err != nil {
			return "", err
		}
		payload["diagnostic"] = normalized
	case "file_completed":
		logical, _ = event["path"].(string)
	}
	return fmt.Sprintf("%02d\x00%s\x00%s", eventRank(eventName), logical, mustCanonicalJSON(payload)), nil
}

func eventRank(eventName string) int {
	switch eventName {
	case "scan_started":
		return 0
	case "profile_declared":
		return 1
	case "node_upsert":
		return 2
	case "dependency_site":
		return 3
	case "edge_upsert":
		return 4
	case "diagnostic":
		return 5
	case "file_completed":
		return 6
	case "profile_completed":
		return 7
	case "scan_completed":
		return 8
	default:
		return 9
	}
}

func mustCanonicalJSON(value any) string {
	encoded, err := canonicalJSON(value)
	if err != nil {
		return fmt.Sprintf("<invalid:%v>", err)
	}
	return encoded
}

func profileScopedNodeKind(kind string) bool {
	switch kind {
	case "build_unit", "external_system", "file", "module", "package_instance", "symbol", "type", "unknown_target":
		return true
	default:
		return false
	}
}

func nodeLogicalID(node map[string]any) (string, error) {
	kind, err := stringField(node, "kind")
	if err != nil {
		return "", err
	}
	if kind == "symbol" || kind == "type" {
		properties, err := objectField(node, "properties")
		if err != nil {
			return "", err
		}
		identity, err := objectField(properties, "canonical_identity")
		if err != nil {
			return "", err
		}
		resolver, err := stringField(identity, "resolver_identity")
		if err != nil {
			return "", err
		}
		return kind + ":" + resolver, nil
	}
	locator, err := stringField(node, "locator")
	if err != nil {
		return "", err
	}
	return kind + ":" + locator, nil
}

func canonicalSite(site map[string]any, nodeIDs map[string]string) (string, error) {
	copy, err := cloneObject(site)
	if err != nil {
		return "", err
	}
	delete(copy, "id")
	normalizeValue(copy, "dependency_site", false, false)
	if err := normalizeReference(copy, "source", nodeIDs); err != nil {
		return "", err
	}
	if err := normalizeStringSlice(copy, "target_ids", nodeIDs, "site target"); err != nil {
		return "", err
	}
	return canonicalJSON(copy)
}

func canonicalEdge(edge map[string]any, nodeIDs, siteIDs map[string]string) (string, error) {
	copy, err := cloneObject(edge)
	if err != nil {
		return "", err
	}
	delete(copy, "id")
	normalizeValue(copy, "edge_upsert", false, false)
	if err := normalizeReference(copy, "source", nodeIDs); err != nil {
		return "", err
	}
	if err := normalizeReference(copy, "target", nodeIDs); err != nil {
		return "", err
	}
	if siteID, ok := copy["site_id"].(string); ok && siteID != "" {
		mapped, err := mappedID(siteIDs, siteID, "edge site")
		if err != nil {
			return "", err
		}
		copy["site_id"] = mapped
	}
	return canonicalJSON(copy)
}

func canonicalDiagnostic(diagnostic map[string]any, maps eventMaps) (string, error) {
	normalized, err := normalizeDiagnostic(diagnostic, maps, false)
	if err != nil {
		return "", err
	}
	return canonicalJSON(normalized)
}

func normalizeDiagnostic(diagnostic map[string]any, maps eventMaps, includeID bool) (map[string]any, error) {
	copy, err := cloneObject(diagnostic)
	if err != nil {
		return nil, err
	}
	normalizeValue(copy, "diagnostic", false, false)
	if includeID {
		rawID, err := stringField(copy, "id")
		if err != nil {
			return nil, err
		}
		mapped, err := mappedID(maps.diagnosticIDs, rawID, "diagnostic")
		if err != nil {
			return nil, err
		}
		copy["id"] = mapped
	} else {
		delete(copy, "id")
	}
	if err := normalizeDiagnosticReferences(copy, maps, "diagnostic"); err != nil {
		return nil, err
	}
	return copy, nil
}

// normalizeDiagnosticReferences only rewrites fields whose protocol meaning
// is a graph reference. Arbitrary diagnostic properties remain visible. An
// unknown value in one of these reference fields is rejected rather than
// replaced with a plausible placeholder.
func normalizeDiagnosticReferences(value any, maps eventMaps, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			fieldPath := path + "." + key
			switch key {
			case "site_id":
				mapped, err := mappedDiagnosticReference(child, maps.siteIDs, fieldPath)
				if err != nil {
					return err
				}
				typed[key] = mapped
			case "node_id", "source_id", "target_id":
				mapped, err := mappedDiagnosticReference(child, maps.nodeIDs, fieldPath)
				if err != nil {
					return err
				}
				typed[key] = mapped
			case "edge_id":
				mapped, err := mappedDiagnosticReference(child, maps.edgeIDs, fieldPath)
				if err != nil {
					return err
				}
				typed[key] = mapped
			case "site_ids":
				if err := normalizeStringSliceAtPath(typed, key, maps.siteIDs, fieldPath); err != nil {
					return err
				}
			case "node_ids", "source_ids", "target_ids":
				if err := normalizeStringSliceAtPath(typed, key, maps.nodeIDs, fieldPath); err != nil {
					return err
				}
			case "edge_ids":
				if err := normalizeStringSliceAtPath(typed, key, maps.edgeIDs, fieldPath); err != nil {
					return err
				}
			default:
				if err := normalizeDiagnosticReferences(child, maps, fieldPath); err != nil {
					return err
				}
			}
		}
	case []any:
		for index, child := range typed {
			if err := normalizeDiagnosticReferences(child, maps, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func mappedDiagnosticReference(value any, ids map[string]string, path string) (string, error) {
	rawID, ok := value.(string)
	if !ok || rawID == "" {
		return "", fmt.Errorf("Go golden diagnostic reference %s is not a non-empty string: %#v", path, value)
	}
	return mappedID(ids, rawID, "diagnostic reference "+path)
}

func normalizeStringSliceAtPath(object map[string]any, key string, ids map[string]string, path string) error {
	values, ok := object[key].([]any)
	if !ok {
		return fmt.Errorf("Go golden diagnostic field %q is not an array: %#v", path, object[key])
	}
	for index, value := range values {
		rawID, ok := value.(string)
		if !ok || rawID == "" {
			return fmt.Errorf("Go golden diagnostic field %q[%d] contains invalid ID: %#v", path, index, value)
		}
		mapped, err := mappedID(ids, rawID, "diagnostic reference "+path)
		if err != nil {
			return err
		}
		values[index] = mapped
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left].(string) < values[right].(string)
	})
	return nil
}

func normalizeValue(value any, eventName string, inProfile, inEnvironment bool) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			switch {
			case key == "scan_id":
				typed[key] = "<scan-id>"
			case key == "profile_id":
				typed[key] = "<profile-id>"
			case key == "profile_ids":
				if values, ok := child.([]any); ok {
					for index := range values {
						values[index] = "<profile-id>"
					}
				}
			case eventName == "scan_started" && key == "root":
				typed[key] = "<scan-root>"
			case inProfile && key == "id":
				typed[key] = "<profile-id>"
			case inProfile && key == "toolchain":
				typed[key] = "<toolchain>"
			case inProfile && key == "target":
				typed[key] = "<profile-target>"
			case inEnvironment && (key == "GOOS" || key == "GOARCH" || key == "CGO_ENABLED"):
				typed[key] = "<host-axis>"
			default:
				childProfile := inProfile
				childEnvironment := inEnvironment
				if inProfile && key == "environment" {
					childProfile = false
					childEnvironment = true
				}
				if key == "profile" && eventName == "profile_declared" {
					childProfile = true
				}
				typed[key] = normalizeValue(child, eventName, childProfile, childEnvironment)
			}
		}
	case []any:
		for index, child := range typed {
			typed[index] = normalizeValue(child, eventName, inProfile, inEnvironment)
		}
	}
	return value
}

func normalizeReference(object map[string]any, key string, ids map[string]string) error {
	rawID, err := stringField(object, key)
	if err != nil {
		return err
	}
	mapped, err := mappedID(ids, rawID, key)
	if err != nil {
		return err
	}
	object[key] = mapped
	return nil
}

func normalizeStringSlice(object map[string]any, key string, ids map[string]string, role string) error {
	values, ok := object[key].([]any)
	if !ok {
		return fmt.Errorf("Go golden event field %q is not an array: %#v", key, object[key])
	}
	for index, value := range values {
		rawID, ok := value.(string)
		if !ok {
			return fmt.Errorf("Go golden event field %q contains non-string value: %#v", key, value)
		}
		mapped, err := mappedID(ids, rawID, role)
		if err != nil {
			return err
		}
		values[index] = mapped
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left].(string) < values[right].(string)
	})
	return nil
}

func mappedID(ids map[string]string, rawID, role string) (string, error) {
	if mapped, ok := ids[rawID]; ok {
		return mapped, nil
	}
	return "", fmt.Errorf("Go golden %s references unknown ID %q", role, rawID)
}

func objectField(object map[string]any, key string) (map[string]any, error) {
	value, ok := object[key].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Go golden event field %q is not an object: %#v", key, object[key])
	}
	return value, nil
}

func stringField(object map[string]any, key string) (string, error) {
	value, ok := object[key].(string)
	if !ok {
		return "", fmt.Errorf("Go golden event field %q is not a string: %#v", key, object[key])
	}
	return value, nil
}

func cloneObject(object map[string]any) (map[string]any, error) {
	data, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("clone Go golden object: %w", err)
	}
	var clone map[string]any
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, fmt.Errorf("decode cloned Go golden object: %w", err)
	}
	return clone, nil
}

func canonicalJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode Go golden identity: %w", err)
	}
	return string(data), nil
}
