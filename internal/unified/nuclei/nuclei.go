// Package nuclei defines the parser for projectdiscovery/nuclei-templates
// YAML files. Stage 4 needs only the metadata required to join templates
// to CVE-IDs and surface the detection signal on a UnifiedAdvisory; the
// template's matcher logic (`http`, `dns`, `network`, …) is intentionally
// not decoded.
//
// Source tree:
//
//	https://github.com/projectdiscovery/nuclei-templates
package nuclei

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template is the decoded view of one Nuclei YAML template.
type Template struct {
	ID   string `yaml:"id"`
	Info Info   `yaml:"info"`

	// Path is the template's path relative to the walk root, set by
	// Walk. Not part of the YAML.
	Path string `yaml:"-"`
}

// Info mirrors the upstream `info` block; only fields the annotator
// surfaces are decoded.
type Info struct {
	Name           string         `yaml:"name"`
	Severity       string         `yaml:"severity"`
	Tags           StringList     `yaml:"tags"`
	Reference      StringList     `yaml:"reference"`
	Classification Classification `yaml:"classification"`
}

// Classification carries the cross-reference IDs Stage 4 joins on.
type Classification struct {
	CVEID StringList `yaml:"cve-id"`
	CWEID StringList `yaml:"cwe-id"`
}

// StringList accepts either a YAML scalar (single string, comma- or
// whitespace-tolerant for `tags`) or a YAML sequence. Nuclei templates
// use both forms across the catalog.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler so a scalar `tags: a,b,c`
// decodes the same as a sequence `tags: [a, b, c]`.
func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		raw := strings.TrimSpace(node.Value)
		if raw == "" {
			*s = nil
			return nil
		}
		// `tags` is comma-joined upstream; references / IDs are usually
		// one per scalar but a defensive split keeps both shapes safe.
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if v := strings.TrimSpace(p); v != "" {
				out = append(out, v)
			}
		}
		*s = out
	case yaml.SequenceNode:
		out := make([]string, 0, len(node.Content))
		for _, c := range node.Content {
			if c.Kind != yaml.ScalarNode {
				return fmt.Errorf("nuclei: expected scalar in sequence, got kind %d", c.Kind)
			}
			out = append(out, c.Value)
		}
		*s = out
	default:
		return fmt.Errorf("nuclei: expected scalar or sequence, got kind %d", node.Kind)
	}
	return nil
}

// Parse decodes one template's YAML bytes.
func Parse(b []byte) (Template, error) {
	var t Template
	if err := yaml.Unmarshal(b, &t); err != nil {
		return Template{}, err
	}
	return t, nil
}

// Walk reads every `*.yaml` / `*.yml` file under root, parses it, and
// returns the templates that carry at least one CVE-ID classification.
// Templates without a CVE-ID join key are silently skipped — they have
// no meaning for Stage 4.
//
// Walk is a no-op (empty result, nil error) when root does not exist,
// so a partial pipeline that ran without `wisteria fetch nuclei` still
// works. A malformed YAML file aborts the walk with the file path.
//
// Reads happen through an os.Root-scoped handle so a symlink inside
// the template tree cannot redirect a ReadFile out of root; mirrors
// the defense the unified walker uses for OSV.
func Walk(ctx context.Context, root string) ([]Template, error) {
	if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("nuclei: open root %s: %w", root, err)
	}
	defer rootFS.Close()

	var out []Template
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !isYAML(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("rel %s: %w", path, err)
		}
		b, err := rootFS.ReadFile(rel)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		tpl, err := Parse(b)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if len(tpl.Info.Classification.CVEID) == 0 {
			return nil
		}
		tpl.Path = rel
		out = append(out, tpl)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
