package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
	authLoginCmd.Flags().StringVar(&loginToken, "token", "", "Authenticate with a token instead of the browser flow (use - to read it from stdin, or set PREFLIGHT_TOKEN)")
	authCmd.AddCommand(authLoginCmd, authLogoutCmd, authStatusCmd)
	rootCmd.AddCommand(authCmd)
}

func runAuthLogin(cmd *cobra.Command, args []string) error {
	client := dashboard.NewClient()
	client.Ctx = cmd.Context()

	// Headless / paste fallback: validate the token and store it. A token
	// on the command line lands in shell history and `ps`, so "-" reads it
	// from stdin and PREFLIGHT_TOKEN reads it from the environment.
	token, err := resolveLoginToken(loginToken, os.Getenv("PREFLIGHT_TOKEN"), os.Stdin)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	loginToken = token
	if loginToken != "" {
		email, err := client.Whoami(loginToken)
		if err != nil {
			return &ExitError{Code: ExitFail, Err: fmt.Errorf("token rejected: %w", err)}
		}
		return saveLogin(client.BaseURL, loginToken, email)
	}

	start, err := client.StartAuth()
	if err != nil {
		return &ExitError{Code: ExitFail, Err: fmt.Errorf("could not start login: %w", err)}
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
	token, err = pollLogin(cmd.Context(), func() (*dashboard.PollStatus, error) { return client.Poll(start.DeviceCode) }, interval, deadline, os.Stdout)
	if err != nil {
		return err
	}
	email, err := client.Whoami(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Could not look up the account email (%v); the login is saved.\n", err)
		email = ""
	}
	return saveLogin(client.BaseURL, token, email)
}

// maxPollFailures is how many polls in a row may fail before login gives
// up (about 30 seconds at the default 2-second interval). A dashboard that
// stays unreachable that long will not come back within the code's
// lifetime often enough to justify a silent ten-minute wait.
const maxPollFailures = 15

// pollLogin polls until the login is approved and returns the token. Each
// failed poll is shown (repeats of the same error collapse into dots) so
// an outage does not look like a pending approval.
func pollLogin(ctx context.Context, poll func() (*dashboard.PollStatus, error), interval time.Duration, deadline time.Time, out io.Writer) (string, error) {
	failures := 0
	lastErr := ""
	for time.Now().Before(deadline) {
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return "", &ExitError{Code: ExitCanceled, Err: ctx.Err()}
		}
		status, err := poll()
		if err != nil {
			var permanent *dashboard.PermanentError
			if errors.As(err, &permanent) {
				fmt.Fprintln(out)
				return "", &ExitError{Code: ExitFail, Err: fmt.Errorf("login failed: %w", err)}
			}
			failures++
			if failures >= maxPollFailures {
				fmt.Fprintln(out)
				return "", &ExitError{Code: ExitFail, Err: fmt.Errorf("login failed: could not reach the dashboard (%d attempts in a row): %w", failures, err)}
			}
			if err.Error() != lastErr {
				lastErr = err.Error()
				fmt.Fprintf(out, "\n  Could not reach the dashboard (%v); retrying", err)
			} else {
				fmt.Fprint(out, ".")
			}
			continue
		}
		if failures > 0 {
			fmt.Fprint(out, "\n  Reconnected; waiting for authorization...")
		}
		failures, lastErr = 0, ""
		switch status.Status {
		case "approved":
			if status.Token == "" {
				fmt.Fprintln(out)
				return "", &ExitError{Code: ExitFail, Err: fmt.Errorf("the dashboard approved the login but sent no token; run 'preflight auth login' again")}
			}
			fmt.Fprintln(out, " done.")
			return status.Token, nil
		case "expired":
			fmt.Fprintln(out)
			return "", &ExitError{Code: ExitFail, Err: fmt.Errorf("the authorization code expired; run 'preflight auth login' again")}
		default:
			fmt.Fprint(out, ".")
		}
	}
	fmt.Fprintln(out)
	return "", &ExitError{Code: ExitFail, Err: fmt.Errorf("timed out waiting for authorization")}
}

// resolveLoginToken picks the token from --token ("-" means stdin) or, when
// the flag is empty, from PREFLIGHT_TOKEN. An empty result means the browser
// flow.
func resolveLoginToken(flag, env string, stdin io.Reader) (string, error) {
	if flag == "-" {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("could not read token from stdin: %w", err)
		}
		token := strings.TrimSpace(line)
		if token == "" {
			return "", fmt.Errorf("no token on stdin")
		}
		return token, nil
	}
	if flag != "" {
		return flag, nil
	}
	return strings.TrimSpace(env), nil
}

func saveLogin(apiURL, token, email string) error {
	creds := &dashboard.Credentials{Token: token, Email: email, APIURL: apiURL}
	if err := creds.Save(); err != nil {
		return &ExitError{Code: ExitFail, Err: fmt.Errorf("could not save credentials: %w", err)}
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
		return &ExitError{Code: ExitFail, Err: fmt.Errorf("could not remove credentials: %w", err)}
	}
	fmt.Println("✓ Logged out")
	return nil
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	creds, err := dashboard.LoadCredentials()
	if err != nil {
		return &ExitError{Code: ExitFail, Err: err}
	}
	if creds == nil || creds.Token == "" {
		fmt.Println("Not logged in. Run 'preflight auth login' to connect your account.")
		return nil
	}
	fmt.Print(authStatusText(creds))
	return nil
}

// authStatusText describes stored credentials. The email is empty when the
// account lookup after login failed; the token still works.
func authStatusText(creds *dashboard.Credentials) string {
	who := "Logged in (account email unknown; run 'preflight auth login' again to look it up)"
	if creds.Email != "" {
		who = "Logged in as " + creds.Email
	}
	return fmt.Sprintf("%s\nDashboard:  %s\n", who, creds.APIURL)
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
