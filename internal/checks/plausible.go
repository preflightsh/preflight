package checks

type PlausibleCheck struct{}

func (c PlausibleCheck) ID() string {
	return "plausible"
}

func (c PlausibleCheck) Title() string {
	return "Plausible Analytics"
}

// Run looks for the Plausible script or one of its packages anywhere in the
// project's templates and source, with comments stripped. It used to read
// five stacks' layout files plus JavaScript under src, app, and components,
// so a script tag in templates/_layout.twig went unseen, and a commented-out
// tag in index.html passed.
func (c PlausibleCheck) Run(ctx Context) (CheckResult, error) {
	if !serviceDeclared(ctx, c.ID()) {
		return serviceSkipped(c.ID(), c.Title(), "Plausible"), nil
	}
	if ctx.serviceCodeMatch(c.ID()) != nil {
		return servicePassed(c.ID(), c.Title(), "Plausible analytics script found"), nil
	}
	if r, ok := serviceEnvPass(ctx, c.ID(), c.Title()); ok {
		return r, nil
	}
	return serviceWarned(c.ID(), c.Title(), "Plausible is declared but script not found in templates",
		"Add the Plausible script tag to your main layout",
		"Example: <script defer data-domain=\"yourdomain.com\" src=\"https://plausible.io/js/script.js\"></script>",
	), nil
}
