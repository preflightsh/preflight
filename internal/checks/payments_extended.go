package checks

import (
	"regexp"
)

// PayPalCheck verifies PayPal is properly set up
var PayPalCheck = ServiceCheck{
	CheckID:     "paypal",
	CheckTitle:  "PayPal",
	EnvPrefixes: []string{"PAYPAL_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`paypal\.com/sdk`),
		regexp.MustCompile(`@paypal/`),
		regexp.MustCompile(`paypal-js`),
		regexp.MustCompile(`PayPalButtons`),
		regexp.MustCompile(`paypalobjects\.com`),
	},
	EnvFoundMsg:  "PayPal configuration found in environment",
	CodeFoundMsg: "PayPal SDK initialization found",
	NotFoundMsg:  "PayPal is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add PayPal SDK script or @paypal/react-paypal-js",
		"Configure PAYPAL_CLIENT_ID in environment",
	},
}

// BraintreeCheck verifies Braintree is properly set up
var BraintreeCheck = ServiceCheck{
	CheckID:     "braintree",
	CheckTitle:  "Braintree",
	EnvPrefixes: []string{"BRAINTREE_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`braintree\.BraintreeGateway`),
		regexp.MustCompile(`Braintree\\Gateway`),
		regexp.MustCompile(`Braintree::`),
		regexp.MustCompile(`braintreepayments`),
		regexp.MustCompile(`braintree-web`),
	},
	EnvFoundMsg:  "Braintree configuration found in environment",
	CodeFoundMsg: "Braintree SDK initialization found",
	NotFoundMsg:  "Braintree is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Initialize Braintree gateway in your application",
		"Configure BRAINTREE_MERCHANT_ID, BRAINTREE_PUBLIC_KEY, BRAINTREE_PRIVATE_KEY",
	},
}

// PaddleCheck verifies Paddle is properly set up
var PaddleCheck = ServiceCheck{
	CheckID:     "paddle",
	CheckTitle:  "Paddle",
	EnvPrefixes: []string{"PADDLE_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`cdn\.paddle\.com`),
		regexp.MustCompile(`Paddle\.Setup`),
		regexp.MustCompile(`Paddle\.Checkout`),
		regexp.MustCompile(`@paddle/paddle-js`),
		regexp.MustCompile(`paddle-node`),
	},
	EnvFoundMsg:  "Paddle configuration found in environment",
	CodeFoundMsg: "Paddle SDK initialization found",
	NotFoundMsg:  "Paddle is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add Paddle.js script to your checkout page",
		"Configure PADDLE_VENDOR_ID in environment",
	},
}

// LemonSqueezyCheck verifies LemonSqueezy is properly set up
var LemonSqueezyCheck = ServiceCheck{
	CheckID:     "lemonsqueezy",
	CheckTitle:  "LemonSqueezy",
	EnvPrefixes: []string{"LEMONSQUEEZY_", "LEMON_SQUEEZY_"},
	CodePatterns: []*regexp.Regexp{
		regexp.MustCompile(`@lemonsqueezy/`),
		regexp.MustCompile(`lemonsqueezy\.com`),
		regexp.MustCompile(`LemonSqueezy`),
	},
	EnvFoundMsg:  "LemonSqueezy configuration found in environment",
	CodeFoundMsg: "LemonSqueezy SDK initialization found",
	NotFoundMsg:  "LemonSqueezy is declared but SDK not found",
	NotFoundSuggestions: []string{
		"Add @lemonsqueezy/lemonsqueezy.js to your project",
		"Configure LEMONSQUEEZY_API_KEY in environment",
	},
}
