// Package issue437golden contains the stable projection used by the Issue 437
// worker golden tests. It deliberately normalizes only profile/toolchain/host
// axes; graph identity and payload drift remains visible to the tests.
package issue437golden

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// NormalizeNDJSON parses a safe worker stream and returns a deterministic
// projection suitable for comparing output captured on different hosts. The
// projection retains event order and sequence numbers, every node property,
// site/evidence field, edge (including structural contains/declares edges),
// file completion, and completion coverage.
func NormalizeNDJSON(data []byte) ([]map[string]any, error) {
	events, err := eventsFromNDJSON(data)
	if err != nil {
		return nil, err
	}
	maps, err := buildEventMaps(events)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		eventName, _ := event["event"].(string)
		normalizeValue(event, eventName, false, false)
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
		}
	}
	return events, nil
}

type eventMaps struct {
	nodeIDs map[string]string
	siteIDs map[string]string
	edgeIDs map[string]string
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
		nodeIDs: map[string]string{},
		siteIDs: map[string]string{},
		edgeIDs: map[string]string{},
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
	return maps, nil
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
