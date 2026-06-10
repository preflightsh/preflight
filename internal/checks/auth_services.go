package checks

import (
	"regexp"
)

// Auth0Check verifies Auth0 is properly set up
var Auth0Check = ServiceCheck{
	CheckID:     "auth0",
	CheckTitle:  "Auth0",
	EnvPrefixes: []string{"AUTH0_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@auth0/`),
		regexp.MustCompile(`auth0\.com`),
		regexp.MustCompile(`Auth0Provider`),
		regexp.MustCompile(`createAuth0Client`),
	},
	EnvFoundMsg:  "Auth0 configuration found in environment",
	CodeFoundMsg: "Auth0 SDK initialization found",
	NotFoundMsg:  "Auth0 is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add AUTH0_DOMAIN and AUTH0_CLIENT_ID to environment",
		"Initialize Auth0 SDK in your application",
	},
}

// ClerkCheck verifies Clerk is properly set up
var ClerkCheck = ServiceCheck{
	CheckID:     "clerk",
	CheckTitle:  "Clerk",
	EnvPrefixes: []string{"CLERK_", "NEXT_PUBLIC_CLERK"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@clerk/`),
		regexp.MustCompile(`ClerkProvider`),
		regexp.MustCompile(`clerk\.com`),
	},
	EnvFoundMsg:  "Clerk configuration found in environment",
	CodeFoundMsg: "Clerk SDK initialization found",
	NotFoundMsg:  "Clerk is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add CLERK_SECRET_KEY and NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
		"Wrap your app with ClerkProvider",
	},
}

// WorkOSCheck verifies WorkOS is properly set up
var WorkOSCheck = ServiceCheck{
	CheckID:     "workos",
	CheckTitle:  "WorkOS",
	EnvPrefixes: []string{"WORKOS_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@workos-inc/`),
		regexp.MustCompile(`workos\.com`),
		regexp.MustCompile(`WorkOS`),
	},
	EnvFoundMsg:  "WorkOS configuration found in environment",
	CodeFoundMsg: "WorkOS SDK initialization found",
	NotFoundMsg:  "WorkOS is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add WORKOS_API_KEY and WORKOS_CLIENT_ID to environment",
	},
}

// FirebaseCheck verifies Firebase is properly set up
var FirebaseCheck = ServiceCheck{
	CheckID:     "firebase",
	CheckTitle:  "Firebase",
	EnvPrefixes: []string{"FIREBASE_", "NEXT_PUBLIC_FIREBASE"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`firebase/app`),
		regexp.MustCompile(`from\s+["']firebase`),
		regexp.MustCompile(`@firebase/`),
		regexp.MustCompile(`firebaseConfig`),
		regexp.MustCompile(`firebase\.google\.com`),
		regexp.MustCompile(`firebase\.initializeApp`),
	},
	EnvFoundMsg:  "Firebase configuration found in environment",
	CodeFoundMsg: "Firebase initialization found",
	NotFoundMsg:  "Firebase is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add Firebase config to your environment",
		"Initialize Firebase with initializeApp()",
	},
}

// SupabaseCheck verifies Supabase is properly set up
var SupabaseCheck = ServiceCheck{
	CheckID:     "supabase",
	CheckTitle:  "Supabase",
	EnvPrefixes: []string{"SUPABASE_", "NEXT_PUBLIC_SUPABASE"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@supabase/`),
		regexp.MustCompile(`supabase\.co`),
		regexp.MustCompile(`supabase\.createClient`),
		regexp.MustCompile(`createClient\s*\([^)]*supabase`),
		regexp.MustCompile(`from\s+["']@supabase`),
	},
	EnvFoundMsg:  "Supabase configuration found in environment",
	CodeFoundMsg: "Supabase initialization found",
	NotFoundMsg:  "Supabase is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add SUPABASE_URL and SUPABASE_ANON_KEY to environment",
		"Initialize Supabase client with createClient()",
	},
}
