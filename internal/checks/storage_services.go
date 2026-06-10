package checks

import (
	"regexp"
)

// AWSS3Check verifies AWS S3 is properly set up
var AWSS3Check = ServiceCheck{
	CheckID:     "aws_s3",
	CheckTitle:  "AWS S3",
	EnvPrefixes: []string{"AWS_", "S3_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@aws-sdk/client-s3`),
		regexp.MustCompile(`aws-sdk.*S3`),
		regexp.MustCompile(`Aws\\S3`),
		regexp.MustCompile(`boto3.*s3`),
		regexp.MustCompile(`s3\.amazonaws\.com`),
	},
	EnvFoundMsg:  "AWS S3 configuration found in environment",
	CodeFoundMsg: "AWS S3 SDK initialization found",
	NotFoundMsg:  "AWS S3 is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to environment",
		"Initialize AWS S3 client in your application",
	},
}

// CloudinaryCheck verifies Cloudinary is properly set up
var CloudinaryCheck = ServiceCheck{
	CheckID:     "cloudinary",
	CheckTitle:  "Cloudinary",
	EnvPrefixes: []string{"CLOUDINARY_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`res\.cloudinary\.com`),
		regexp.MustCompile(`@cloudinary/`),
		regexp.MustCompile(`cloudinary\.v2`),
		regexp.MustCompile(`cloudinary\.config`),
		regexp.MustCompile(`cloudinary\.uploader`),
		regexp.MustCompile(`from\s+["']cloudinary["']`),
	},
	EnvFoundMsg:  "Cloudinary configuration found in environment",
	CodeFoundMsg: "Cloudinary SDK initialization found",
	NotFoundMsg:  "Cloudinary is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME to environment",
		"Initialize Cloudinary SDK in your application",
	},
}

// CloudflareCheck verifies Cloudflare is properly set up
var CloudflareCheck = ServiceCheck{
	CheckID:     "cloudflare",
	CheckTitle:  "Cloudflare",
	EnvPrefixes: []string{"CLOUDFLARE_", "CF_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@cloudflare/`),
		regexp.MustCompile(`cdnjs\.cloudflare\.com`),
		regexp.MustCompile(`api\.cloudflare\.com`),
		regexp.MustCompile(`cloudflare\.com/client`),
		regexp.MustCompile(`wrangler\.toml`),
		regexp.MustCompile(`wrangler deploy`),
	},
	EnvFoundMsg:  "Cloudflare configuration found in environment",
	CodeFoundMsg: "Cloudflare integration found",
	NotFoundMsg:  "Cloudflare is declared but integration not found",
	NotFoundSuggestions: []string{
		"Add CLOUDFLARE_API_TOKEN to environment",
		"Configure Cloudflare Workers or Pages if applicable",
	},
}
