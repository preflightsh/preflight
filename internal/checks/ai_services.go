package checks

import (
	"regexp"
)

// AI provider checks. All follow the standard ServiceCheck shape: declared →
// env var → SDK usage in code.

// OpenAICheck verifies OpenAI is properly set up.
var OpenAICheck = ServiceCheck{
	CheckID:     "openai",
	CheckTitle:  "OpenAI",
	EnvPrefixes: []string{"OPENAI_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`new OpenAI\(`),
		regexp.MustCompile(`OpenAI\(\s*\{`),
		regexp.MustCompile(`api\.openai\.com`),
		regexp.MustCompile(`from\s+["']openai["']`),
		regexp.MustCompile(`require\s*\(\s*["']openai["']\)`),
		regexp.MustCompile(`import\s+openai`),
	},
	EnvFoundMsg:  "OpenAI API key found in environment",
	CodeFoundMsg: "OpenAI SDK initialization found",
	NotFoundMsg:  "OpenAI is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add OPENAI_API_KEY to environment",
		"Initialize OpenAI client in your application",
	},
}

// AnthropicCheck verifies Anthropic is properly set up.
var AnthropicCheck = ServiceCheck{
	CheckID:     "anthropic",
	CheckTitle:  "Anthropic",
	EnvPrefixes: []string{"ANTHROPIC_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@anthropic-ai/sdk`),
		regexp.MustCompile(`new Anthropic\(`),
		regexp.MustCompile(`Anthropic\(\s*\{`),
		regexp.MustCompile(`api\.anthropic\.com`),
		regexp.MustCompile(`from\s+["']@anthropic-ai`),
		regexp.MustCompile(`import\s+anthropic`),
	},
	EnvFoundMsg:  "Anthropic API key found in environment",
	CodeFoundMsg: "Anthropic SDK initialization found",
	NotFoundMsg:  "Anthropic is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add ANTHROPIC_API_KEY to environment",
		"Initialize Anthropic client in your application",
	},
}

// GoogleAICheck verifies Google AI is properly set up.
var GoogleAICheck = ServiceCheck{
	CheckID:     "google_ai",
	CheckTitle:  "Google AI",
	EnvPrefixes: []string{"GOOGLE_AI_", "GEMINI_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@google/generative-ai`),
		regexp.MustCompile(`generativelanguage\.googleapis\.com`),
		regexp.MustCompile(`GoogleGenerativeAI`),
		regexp.MustCompile(`gemini-pro`),
		regexp.MustCompile(`gemini-1\.5`),
		regexp.MustCompile(`models/gemini`),
	},
	EnvFoundMsg:  "Google AI API key found in environment",
	CodeFoundMsg: "Google AI SDK initialization found",
	NotFoundMsg:  "Google AI is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add GOOGLE_AI_API_KEY or GEMINI_API_KEY to environment",
		"Initialize Google AI client in your application",
	},
}

// MistralCheck verifies Mistral is properly set up.
var MistralCheck = ServiceCheck{
	CheckID:     "mistral",
	CheckTitle:  "Mistral AI",
	EnvPrefixes: []string{"MISTRAL_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@mistralai/`),
		regexp.MustCompile(`mistralai`),
		regexp.MustCompile(`api\.mistral\.ai`),
	},
	EnvFoundMsg:  "Mistral AI API key found in environment",
	CodeFoundMsg: "Mistral AI SDK initialization found",
	NotFoundMsg:  "Mistral AI is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add MISTRAL_API_KEY to environment",
		"Initialize Mistral client in your application",
	},
}

// CohereCheck verifies Cohere is properly set up.
var CohereCheck = ServiceCheck{
	CheckID:     "cohere",
	CheckTitle:  "Cohere",
	EnvPrefixes: []string{"COHERE_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`cohere-ai`),
		regexp.MustCompile(`api\.cohere\.ai`),
		regexp.MustCompile(`cohere\.ai`),
		regexp.MustCompile(`CohereClient`),
		regexp.MustCompile(`from\s+["']cohere["']`),
		regexp.MustCompile(`import\s+cohere`),
	},
	EnvFoundMsg:  "Cohere API key found in environment",
	CodeFoundMsg: "Cohere SDK initialization found",
	NotFoundMsg:  "Cohere is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add COHERE_API_KEY to environment",
		"Initialize Cohere client in your application",
	},
}

// ReplicateCheck verifies Replicate is properly set up.
var ReplicateCheck = ServiceCheck{
	CheckID:     "replicate",
	CheckTitle:  "Replicate",
	EnvPrefixes: []string{"REPLICATE_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`api\.replicate\.com`),
		regexp.MustCompile(`replicate\.run\(`),
		regexp.MustCompile(`replicate\.predictions`),
		regexp.MustCompile(`from\s+["']replicate["']`),
		regexp.MustCompile(`import\s+replicate`),
		regexp.MustCompile(`new Replicate\(`),
	},
	EnvFoundMsg:  "Replicate API token found in environment",
	CodeFoundMsg: "Replicate SDK initialization found",
	NotFoundMsg:  "Replicate is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add REPLICATE_API_TOKEN to environment",
		"Initialize Replicate client in your application",
	},
}

// HuggingFaceCheck verifies Hugging Face is properly set up.
var HuggingFaceCheck = ServiceCheck{
	CheckID:     "huggingface",
	CheckTitle:  "Hugging Face",
	EnvPrefixes: []string{"HUGGINGFACE_", "HF_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@huggingface/`),
		regexp.MustCompile(`huggingface\.co`),
		regexp.MustCompile(`HfInference`),
		regexp.MustCompile(`from\s+["']@huggingface`),
		regexp.MustCompile(`from\s+transformers\s+import`),
		regexp.MustCompile(`import\s+transformers`),
	},
	EnvFoundMsg:  "Hugging Face API token found in environment",
	CodeFoundMsg: "Hugging Face SDK initialization found",
	NotFoundMsg:  "Hugging Face is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add HUGGINGFACE_API_TOKEN or HF_TOKEN to environment",
		"Initialize Hugging Face client in your application",
	},
}

// GrokCheck verifies Grok (xAI) is properly set up.
var GrokCheck = ServiceCheck{
	CheckID:     "grok",
	CheckTitle:  "Grok (xAI)",
	EnvPrefixes: []string{"XAI_", "GROK_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`api\.x\.ai`),
		regexp.MustCompile(`xai-sdk`),
		regexp.MustCompile(`grok-`),
	},
	EnvFoundMsg:  "Grok API key found in environment",
	CodeFoundMsg: "Grok SDK initialization found",
	NotFoundMsg:  "Grok is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add XAI_API_KEY to environment",
		"Initialize Grok client in your application",
	},
}

// PerplexityCheck verifies Perplexity is properly set up.
var PerplexityCheck = ServiceCheck{
	CheckID:     "perplexity",
	CheckTitle:  "Perplexity",
	EnvPrefixes: []string{"PERPLEXITY_", "PPLX_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`api\.perplexity\.ai`),
		regexp.MustCompile(`perplexity\.ai`),
		regexp.MustCompile(`PerplexityClient`),
		regexp.MustCompile(`from\s+["']perplexity["']`),
	},
	EnvFoundMsg:  "Perplexity API key found in environment",
	CodeFoundMsg: "Perplexity SDK initialization found",
	NotFoundMsg:  "Perplexity is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add PERPLEXITY_API_KEY to environment",
		"Initialize Perplexity client in your application",
	},
}

// TogetherAICheck verifies Together AI is properly set up.
var TogetherAICheck = ServiceCheck{
	CheckID:     "together_ai",
	CheckTitle:  "Together AI",
	EnvPrefixes: []string{"TOGETHER_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`together-ai`),
		regexp.MustCompile(`api\.together\.xyz`),
		regexp.MustCompile(`together\.ai`),
	},
	EnvFoundMsg:  "Together AI API key found in environment",
	CodeFoundMsg: "Together AI SDK initialization found",
	NotFoundMsg:  "Together AI is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add TOGETHER_API_KEY to environment",
		"Initialize Together AI client in your application",
	},
}
