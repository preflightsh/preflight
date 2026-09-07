package cmd

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/preflightsh/preflight/internal/dashboard"
	"github.com/spf13/cobra"
)

var loginToken string

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication with your Preflight account",
	Long:  `Log in to app.preflight.sh to publish scan results and view them in your dashboard.`,
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate this CLI with your Preflight account",
	RunE:  runAuthLogin,
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Sign out and remove stored credentials",
	RunE:  runAuthLogout,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current authentication status",
	RunE:  runAuthStatus,
}

func init() {
	authLoginCmd.Flags().StringVar(&loginToken, "token", "", "Authenticate with a pasted token instead of the browser flow")
	authCmd.AddCommand(authLoginCmd, authLogoutCmd, authStatusCmd)
	rootCmd.AddCommand(authCmd)
}

func runAuthLogin(cmd *cobra.Command, args []string) error {
	client := dashboard.NewClient()

	// Headless / paste fallback: validate the token and store it.
	if loginToken != "" {
		email, err := client.Whoami(loginToken)
		if err != nil {
			return &ExitError{Code: 1, Err: fmt.Errorf("token rejected: %w", err)}
		}
		return saveLogin(client.BaseURL, loginToken, email)
	}

	start, err := client.StartAuth()
	if err != nil {
		return &ExitError{Code: 1, Err: fmt.Errorf("could not start login: %w", err)}
	}

	fmt.Println()
	fmt.Printf("  Your authorization code: %s\n", start.UserCode)
	fmt.Printf("  Opening %s\n", start.VerifyURL)
	fmt.Println("  (If your browser doesn't open, paste that URL in manually.)")
	fmt.Println()
	openBrowser(start.VerifyURL)

	interval := time.Duration(start.Interval) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	deadline := time.Now().Add(10 * time.Minute)

	fmt.Print("  Waiting for you to authorize in the browser...")
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		status, err := client.Poll(start.DeviceCode)
		if err != nil {
			continue // transient; keep polling
		}
		switch status.Status {
		case "approved":
			fmt.Println(" done.")
			email, err := client.Whoami(status.Token)
			if err != nil {
				email = ""
			}
			return saveLogin(client.BaseURL, status.Token, email)
		case "expired":
			fmt.Println()
			return &ExitError{Code: 1, Err: fmt.Errorf("the authorization code expired; run 'preflight auth login' again")}
		default:
			fmt.Print(".")
		}
	}
	fmt.Println()
	return &ExitError{Code: 1, Err: fmt.Errorf("timed out waiting for authorization")}
}

func saveLogin(apiURL, token, email string) error {
	creds := &dashboard.Credentials{Token: token, Email: email, APIURL: apiURL}
	if err := creds.Save(); err != nil {
		return &ExitError{Code: 1, Err: fmt.Errorf("could not save credentials: %w", err)}
	}
	if email != "" {
		fmt.Printf("\n✓ Logged in as %s\n", email)
	} else {
		fmt.Println("\n✓ Logged in")
	}
	return nil
}

func runAuthLogout(cmd *cobra.Command, args []string) error {
	if err := dashboard.ClearCredentials(); err != nil {
		return &ExitError{Code: 1, Err: fmt.Errorf("could not remove credentials: %w", err)}
	}
	fmt.Println("✓ Logged out")
	return nil
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	creds, err := dashboard.LoadCredentials()
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	if creds == nil || creds.Token == "" {
		fmt.Println("Not logged in. Run 'preflight auth login' to connect your account.")
		return nil
	}
	fmt.Printf("Logged in as %s\n", creds.Email)
	fmt.Printf("Dashboard:  %s\n", creds.APIURL)
	return nil
}

// openBrowser best-effort opens a URL in the user's default browser. Failure is
// non-fatal: the URL is always printed so the user can open it manually.
//
// The URL comes from the dashboard's auth response. Only web URLs are handed
// to the OS opener: `open` and `xdg-open` will happily launch file:// paths
// or other registered schemes, which a misconfigured PREFLIGHT_API_URL
// should not be able to trigger.
func openBrowser(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return
	}
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	args = append(args, rawURL)
	_ = exec.Command(cmd, args...).Start()
}
