package unifier

import (
	"net/url"
	"sort"
	"strings"

	"github.com/masahiro331/wisteria/internal/unified"
)

// mergeReferences normalizes URLs (lowercase scheme/host, strip trailing
// slash on non-root paths, drop fragment), dedups by the normalized URL,
// unions per-URL tags, and sorts by normalized URL (§8.2).
//
// Malformed URLs that net/url can't parse are kept verbatim so the
// pipeline never silently drops upstream data; they just don't benefit
// from normalization.
func mergeReferences(in []unified.Reference) []unified.Reference {
	if len(in) == 0 {
		return nil
	}
	type bucket struct {
		url  string
		tags map[string]struct{}
	}
	buckets := make(map[string]*bucket)
	for _, ref := range in {
		key := normalizeURL(ref.URL)
		b, ok := buckets[key]
		if !ok {
			b = &bucket{url: key, tags: make(map[string]struct{})}
			buckets[key] = b
		}
		for _, tag := range ref.Tags {
			b.tags[tag] = struct{}{}
		}
	}
	out := make([]unified.Reference, 0, len(buckets))
	for _, b := range buckets {
		var tags []string
		if len(b.tags) > 0 {
			tags = make([]string, 0, len(b.tags))
			for t := range b.tags {
				tags = append(tags, t)
			}
			sort.Strings(tags)
		}
		out = append(out, unified.Reference{URL: b.url, Tags: tags})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// normalizeURL applies the §8.2 rules. Returns the input unchanged when
// net/url rejects it so we don't silently mangle malformed entries.
func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.RawFragment = ""
	if strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimRight(u.Path, "/")
		if u.RawPath != "" {
			u.RawPath = strings.TrimRight(u.RawPath, "/")
		}
	}
	return u.String()
}
