package checks

import (
	"regexp"
)

// RabbitMQCheck verifies RabbitMQ is properly set up
var RabbitMQCheck = ServiceCheck{
	CheckID:     "rabbitmq",
	CheckTitle:  "RabbitMQ",
	EnvPrefixes: []string{"RABBITMQ_", "AMQP_", "CLOUDAMQP_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`amqp://`),
		regexp.MustCompile(`amqps://`),
		regexp.MustCompile(`amqplib`),
		// The Ruby and Python clients, as they are used: a bare "bunny" or
		// "pika" is a word (and BunnyCDN).
		regexp.MustCompile(`\bBunny\.new\b|require ['"]bunny['"]`),
		regexp.MustCompile(`(?m)^\s*import\s+pika\b|\bpika\.(?:BlockingConnection|ConnectionParameters|URLParameters)\b`),
	},
	CodeFoundMsg: "RabbitMQ connection found",
	NotFoundMsg:  "RabbitMQ is declared but connection not found",
	NotFoundSuggestions: []string{
		"Add RABBITMQ_URL or AMQP_URL to environment",
	},
}

// ElasticsearchCheck verifies Elasticsearch is properly set up
var ElasticsearchCheck = ServiceCheck{
	CheckID:     "elasticsearch",
	CheckTitle:  "Elasticsearch",
	EnvPrefixes: []string{"ELASTICSEARCH_", "ELASTIC_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@elastic/elasticsearch`),
		regexp.MustCompile(`elasticsearch-py`),
		regexp.MustCompile(`Elasticsearch::Client`),
		regexp.MustCompile(`elastic\.co`),
	},
	CodeFoundMsg: "Elasticsearch client found",
	NotFoundMsg:  "Elasticsearch is declared but client not found",
	NotFoundSuggestions: []string{
		"Add ELASTICSEARCH_URL to environment",
		"Initialize Elasticsearch client in your application",
	},
}

// ConvexCheck verifies Convex is properly set up
var ConvexCheck = ServiceCheck{
	CheckID:     "convex",
	CheckTitle:  "Convex",
	EnvPrefixes: []string{"CONVEX_", "NEXT_PUBLIC_CONVEX"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`convex/_generated`),
		regexp.MustCompile(`ConvexProvider`),
		regexp.MustCompile(`convex\.dev`),
		regexp.MustCompile(`@convex/`),
	},
	CodeFoundMsg: "Convex initialization found",
	NotFoundMsg:  "Convex is declared but initialization not found",
	NotFoundSuggestions: []string{
		"Add CONVEX_URL to environment",
		"Wrap your app with ConvexProvider",
	},
}
