package worker

import (
	"encoding/json"
	"fmt"
	"io"
)

type eventEmitter struct {
	encoder *json.Encoder
	scanID  string
	seq     uint64
}

func Emit(writer io.Writer, scanID string, result Result) error {
	emitter := newEventEmitter(writer, scanID)
	if err := emitter.write("scan_started", map[string]any{
		"root": result.Root, "profile_ids": []string{result.Profile.ID}, "project_code_executed": false, "safe_mode": true,
	}); err != nil {
		return err
	}
	if err := emitter.write("profile_declared", map[string]any{"profile": result.Profile}); err != nil {
		return err
	}
	for _, node := range result.Nodes {
		if err := emitter.write("node_upsert", map[string]any{"node": node}); err != nil {
			return err
		}
	}
	for _, site := range result.Sites {
		if err := emitter.write("dependency_site", map[string]any{"site": site}); err != nil {
			return err
		}
	}
	for _, edge := range result.Edges {
		if err := emitter.write("edge_upsert", map[string]any{"edge": edge}); err != nil {
			return err
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if err := emitter.write("diagnostic", map[string]any{"diagnostic": diagnostic}); err != nil {
			return err
		}
	}
	for _, file := range result.Files {
		fields := map[string]any{
			"path": file.Path, "discovered_sites": file.DiscoveredSites, "emitted_sites": file.EmittedSites,
			"skipped_sites": file.SkippedSites, "skipped": file.Skipped,
		}
		if file.Reason != "" {
			fields["reason"] = file.Reason
		}
		if err := emitter.write("file_completed", fields); err != nil {
			return err
		}
	}
	if err := emitter.write("profile_completed", map[string]any{"profile_id": result.Profile.ID, "coverage": result.Coverage}); err != nil {
		return err
	}
	return emitter.write("scan_completed", map[string]any{"coverage": result.Coverage})
}

func EmitFailure(writer io.Writer, scanID, root string, scanErr error) error {
	emitter := newEventEmitter(writer, scanID)
	if err := emitter.write("scan_started", map[string]any{"root": root, "profile_ids": []string{}, "project_code_executed": false, "safe_mode": true}); err != nil {
		return err
	}
	diagnostic := Diagnostic{
		ID: stableID("diagnostic", "scan-failure", root, scanErr.Error()), Code: "scan_failure",
		Severity: "error", Message: scanErr.Error(), Recoverable: false,
	}
	if err := emitter.write("diagnostic", map[string]any{"diagnostic": diagnostic}); err != nil {
		return err
	}
	coverage := Coverage{ProjectCodeExecuted: false, Completeness: []string{}, Reasons: []string{"scan-failure"}}
	return emitter.write("scan_completed", map[string]any{"coverage": coverage})
}

func newEventEmitter(writer io.Writer, scanID string) *eventEmitter {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &eventEmitter{encoder: encoder, scanID: scanID}
}

func (e *eventEmitter) write(event string, fields map[string]any) error {
	e.seq++
	record := map[string]any{
		"event": event, "protocol_version": ProtocolVersion, "scan_id": e.scanID,
		"adapter": AdapterName, "adapter_version": AdapterVersion, "seq": e.seq,
	}
	for key, value := range fields {
		record[key] = value
	}
	if err := e.encoder.Encode(record); err != nil {
		return fmt.Errorf("encode %s event: %w", event, err)
	}
	return nil
}
