package checks

import "testing"

// TestDebugGuardForms: every language's development guard keeps its debug
// statement out of the findings, as v0.23 did, while production guards,
// negated development guards, else branches, and closed blocks still flag.
func TestDebugGuardForms(t *testing.T) {
	cases := []struct {
		name, file, body string
		found            bool
	}{
		// JavaScript
		{"node env not production", "a.js", "if (process.env.NODE_ENV !== 'production') {\n  console.log('x');\n}\n", false},
		{"node env development inline", "a.js", "if (process.env.NODE_ENV === 'development') console.log('x');\n", false},
		{"and guard", "a.js", "isDev && console.log('x');\n", false},
		{"parenthesized and guard", "a.js", "(process.env.NODE_ENV !== 'production') && console.log('x');\n", false},
		{"ternary guard", "a.js", "const x = isDev ? console.log('x') : null;\n", false},
		{"ternary else branch", "a.js", "const x = isDev ? null : console.log('x');\n", true},
		{"and guard on production", "a.js", "isProduction && console.log('x');\n", true},
		{"vite dev block", "a.js", "if (import.meta.env.DEV) {\n  console.log('x');\n}\n", false},
		{"not vite prod", "a.js", "if (!import.meta.env.PROD) {\n  console.log('x');\n}\n", false},
		{"not production", "a.js", "if (!isProduction) {\n  console.log('x');\n}\n", false},
		{"debug flag", "a.js", "if (DEBUG) {\n  console.log('x');\n}\n", false},
		{"dev global", "a.js", "if (__DEV__) {\n  console.log('x');\n}\n", false},
		{"dev and more", "a.js", "if (isDev && verbose) {\n  console.log('x');\n}\n", false},
		{"dev or other", "a.js", "if (isDev || user.isAdmin) {\n  console.log('x');\n}\n", true},
		{"nested block", "a.js", "if (isDev) {\n  for (const x of xs) {\n    console.log(x);\n  }\n}\n", false},
		{"braceless next line", "a.js", "if (isDev)\n  console.log('x');\n", false},
		{"braceless body then unguarded", "a.js", "if (isDev)\n  work();\nconsole.log('x');\n", true},
		{"allman brace", "a.js", "if (isDev)\n{\n  console.log('x');\n}\n", false},
		{"else if dev", "a.js", "if (a) {\n  work();\n} else if (isDev) {\n  console.log('x');\n}\n", false},
		{"else branch", "a.js", "if (isDev) {\n  work();\n} else {\n  console.log('x');\n}\n", true},
		{"same line else", "a.js", "if (isDev) work(); else console.log('x');\n", true},
		{"unguarded", "a.js", "console.log('x');\n", true},
		{"production block", "a.js", "if (process.env.NODE_ENV === 'production') {\n  console.log('x');\n}\n", true},
		{"device is not dev", "a.js", "if (isDeviceMobile) {\n  console.log('x');\n}\n", true},
		{"sveltekit dev", "a.js", "import { dev } from '$app/environment';\nif (dev) {\n  console.log('x');\n}\n", false},
		{"ejs block", "a.ejs", "<% if (isDev) { %>\n<script>console.log('x')</script>\n<% } %>\n", false},

		// Twig (Craft, Symfony)
		{"twig devMode same line", "a.twig", "<script>\n  {% if devMode %}console.log('x');{% endif %}\n</script>\n", false},
		{"twig devMode block", "a.twig", "{% if craft.app.config.general.devMode %}\n<script>console.log('x')</script>\n{% endif %}\n", false},
		{"twig app.debug", "a.twig", "{% if app.debug %}\n{{ dump(user) }}\n{% endif %}\n", false},
		{"twig after endif", "a.twig", "{% if devMode %}\n<p>x</p>\n{% endif %}\n<script>console.log('x')</script>\n", true},
		{"twig else", "a.twig", "{% if devMode %}\n<p>x</p>\n{% else %}\n<script>console.log('x')</script>\n{% endif %}\n", true},
		{"twig not devMode", "a.twig", "{% if not devMode %}\n<script>console.log('x')</script>\n{% endif %}\n", true},
		{"twig nested for", "a.twig", "{% if devMode %}\n{% for u in users %}\n{{ dump(u) }}\n{% endfor %}\n{% endif %}\n", false},

		// ERB (Rails)
		{"erb development", "a.erb", "<% if Rails.env.development? %>\n<script>console.log('x')</script>\n<% end %>\n", false},
		{"erb unless production", "a.erb", "<% unless Rails.env.production? %>\n<script>console.log('x')</script>\n<% end %>\n", false},
		{"erb after end", "a.erb", "<% if Rails.env.development? %>\n<p>x</p>\n<% end %>\n<script>console.log('x')</script>\n", true},
		{"erb do block inside", "a.erb", "<% if Rails.env.development? %>\n<% @items.each do |i| %>\n<% end %>\n<script>console.log('x')</script>\n<% end %>\n", false},
		{"erb production", "a.erb", "<% if Rails.env.production? %>\n<script>console.log('x')</script>\n<% end %>\n", true},

		// Ruby
		{"ruby block", "a.rb", "if Rails.env.development?\n  binding.pry\nend\n", false},
		{"ruby modifier", "a.rb", "binding.pry if Rails.env.development?\n", false},
		{"ruby modifier other", "a.rb", "binding.pry if ENV['X']\n", true},
		{"ruby after block", "a.rb", "if Rails.env.development?\n  work\nend\nbinding.pry\n", true},

		// Blade (Laravel)
		{"blade config debug", "a.blade.php", "@if(config('app.debug'))\n<script>console.log('x')</script>\n@endif\n", false},
		{"blade env local", "a.blade.php", "@env('local')\n<script>console.log('x')</script>\n@endenv\n", false},
		{"blade isLocal", "a.blade.php", "@if(app()->isLocal())\n{{ dd($user) }}\n@endif\n", false},
		{"blade unless production", "a.blade.php", "@unless(app()->environment('production'))\n<script>console.log('x')</script>\n@endunless\n", false},
		{"blade production", "a.blade.php", "@production\n<script>console.log('x')</script>\n@endproduction\n", true},
		{"blade after endif", "a.blade.php", "@if(config('app.debug'))\n<p>x</p>\n@endif\n<script>console.log('x')</script>\n", true},
		{"blade else", "a.blade.php", "@if(config('app.debug'))\n<p>x</p>\n@else\n<script>console.log('x')</script>\n@endif\n", true},

		// PHP
		{"php app debug", "a.php", "<?php\nif (config('app.debug')) {\n  dump($user);\n}\n", false},
		{"php environment local", "a.php", "<?php\nif (app()->environment('local')) {\n  dump($user);\n}\n", false},

		// Django / Python
		{"django debug", "a.html", "{% if debug %}\n<script>console.log('x')</script>\n{% endif %}\n", false},
		{"python settings debug", "a.py", "if settings.DEBUG:\n    breakpoint()\n", false},
		{"python not debug", "a.py", "if not settings.DEBUG:\n    breakpoint()\n", true},
		{"python after block", "a.py", "if settings.DEBUG:\n    work()\nbreakpoint()\n", true},

		// Rust
		{"rust cfg attribute", "a.rs", "#[cfg(debug_assertions)]\nfn dump(x: &X) {\n    dbg!(x);\n}\n", false},
		{"rust cfg macro", "a.rs", "fn f(x: &X) {\n    if cfg!(debug_assertions) {\n        dbg!(x);\n    }\n}\n", false},
		{"rust cfg not", "a.rs", "#[cfg(not(debug_assertions))]\nfn dump(x: &X) {\n    dbg!(x);\n}\n", true},

		// Hugo, Handlebars, Svelte
		{"hugo server", "a.html", "{{ if hugo.IsServer }}\n<script>console.log('x')</script>\n{{ end }}\n", false},
		{"hugo after end", "a.html", "{{ if hugo.IsServer }}\n{{ range .Pages }}{{ end }}\n{{ end }}\n<script>console.log('x')</script>\n", true},
		{"handlebars", "a.hbs", "{{#if isDev}}\n<script>console.log('x')</script>\n{{/if}}\n", false},
		{"svelte", "a.svelte", "{#if dev}\n<script>console.log('x')</script>\n{/if}\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, tc.file, tc.body)
			got := scanForDebugStatements(root, nil)
			if (len(got) > 0) != tc.found {
				t.Fatalf("findings=%v want found=%v", got, tc.found)
			}
		})
	}
}
