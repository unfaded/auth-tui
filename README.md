# auth-tui

Terminal TOTP authenticator

# Usage

Run without arguments to display codes:

    auth-tui

Import secrets from a file containing otpauth:// URIs (one per line):

    auth-tui import secrets.txt

Export your stored secrets:

    auth-tui export backup.txt

Use a different secrets file:

    auth-tui -f /path/to/secrets

# Storage

Secrets are stored in `~/.auth-tui` as plain otpauth:// URIs.

# Supported

- SHA1, SHA256, SHA512 algorithms
- Custom digit counts and periods
- Standard otpauth:// URI format (compatible with Google Authenticator exports)