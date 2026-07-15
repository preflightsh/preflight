package checks

import "testing"

// The WordPress branch used `schema.*graph`, which fires on any line
// containing both words. Ordinary GraphQL setup does exactly that, so a
// GraphQL API with no Schema.org markup at all passed the check.
func TestHasStructuredData(t *testing.T) {
	cases := []struct {
		name  string
		stack string
		body  string
		want  bool
	}{
		{
			name:  "graphql server setup is not structured data",
			stack: "node",
			body: "import { makeExecutableSchema } from '@graphql-tools/schema'\n" +
				"const schema = makeExecutableSchema({ typeDefs, resolvers })\n",
			want: false,
		},
		{
			name:  "graphql schema stitching is not structured data",
			stack: "node",
			body:  "const schema = stitchSchemas({ subschemas })\nexport { schema } from './graphql'\n",
			want:  false,
		},
		{
			name:  "json-ld script tag",
			stack: "static",
			body:  `<script type="application/ld+json">{"@type":"Organization"}</script>`,
			want:  true,
		},
		{
			name:  "schema.org context",
			stack: "static",
			body:  `{"@context":"https://schema.org","@type":"WebSite"}`,
			want:  true,
		},
		{
			name:  "yoast schema graph class",
			stack: "wordpress",
			body:  `<script class="yoast-schema-graph">{"x":1}</script>`,
			want:  true,
		},
		{
			name:  "at-graph key",
			stack: "wordpress",
			body:  `{"@graph": [{"@type":"Article"}]}`,
			want:  true,
		},
		{
			name:  "rank math",
			stack: "wordpress",
			body:  "add_filter('rank_math/json_ld', 'x');",
			want:  true,
		},
		{
			name:  "no structured data",
			stack: "static",
			body:  "<html><head><title>x</title></head><body>hi</body></html>",
			want:  false,
		},
		{
			name:  "commented-out json-ld does not count",
			stack: "static",
			body:  `<!-- <script type="application/ld+json">{"@type":"Org"}</script> -->`,
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasStructuredData(tc.body, tc.stack); got != tc.want {
				t.Errorf("hasStructuredData(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
