package config

import (
	"strings"
	"testing"
)

// Substring matches on package.json used to make "sanity" and "contentful"
// win over the real framework, and any file named "craft" meant Craft CMS.
func TestDetectStackDependencyMatching(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"sanity-check script is not Sanity", map[string]string{
			"package.json":   `{"scripts":{"sanity-check":"node x.js"},"dependencies":{"react":"^18"}}`,
			"vite.config.ts": "export default {}",
		}, "vite"},
		{"react app using the contentful SDK", map[string]string{
			"package.json":   `{"dependencies":{"react":"^18","contentful":"^10"}}`,
			"vite.config.ts": "export default {}",
		}, "vite"},
		{"sanity studio", map[string]string{
			"package.json":     `{"dependencies":{"sanity":"^3","react":"^18"}}`,
			"sanity.config.ts": "export default {}",
		}, "sanity"},
		{"bare contentful project", map[string]string{
			"package.json": `{"dependencies":{"contentful":"^10"}}`,
		}, "contentful"},
		{"craft directory is not Craft CMS", map[string]string{
			"craft/notes.txt": "hello",
			"index.php":       "<?php echo 1;",
		}, "php"},
		{"craft console script", map[string]string{
			"craft":     "#!/usr/bin/env php\n<?php\n// Craft console application\n",
			"index.php": "<?php echo 1;",
		}, "craft"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectStack(writeProject(t, tc.files)); got != tc.want {
				t.Errorf("DetectStack = %q, want %q", got, tc.want)
			}
		})
	}
}

// Every caller lowercases content first, so mixed-case patterns never matched.
func TestDetectServicesBraintreeAndBunny(t *testing.T) {
	cases := []struct {
		name    string
		content string
		svc     string
		want    bool
	}{
		{"braintree npm dependency", `{"dependencies":{"braintree":"^3"}}`, "braintree", true},
		{"braintree gem", "gem 'braintree'\n", "braintree", true},
		{"braintree env key", "BRAINTREE_MERCHANT_ID=abc\n", "braintree", true},
		{"bunny gem", "gem \"bunny\"\n", "rabbitmq", true},
		{"bunnycdn package is not rabbitmq", `{"dependencies":{"bunnycdn-storage":"^1"}}`, "rabbitmq", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			services := map[string]bool{}
			detectServicesFromContent(strings.ToLower(tc.content), services, "node")
			if services[tc.svc] != tc.want {
				t.Errorf("%s detected = %v, want %v", tc.svc, services[tc.svc], tc.want)
			}
		})
	}
}
