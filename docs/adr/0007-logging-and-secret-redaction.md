# ADR 0007: Logging and secret redaction

Status: Proposed. Implements akash's standing rule: never log, print or send
any secret value or fragment.

## Decision

- Every process logs through `logging.NewHandler`, a `log/slog` handler that:
  - replaces the value of any attribute whose key names a secret (password,
    token, secret, API key, private key, credential, authorization, cookie,
    DSN and similar, after normalising case and separators);
  - scrubs message text and string values for credentials in URLs and DSNs,
    bearer and basic credentials, key=value secrets, PEM private keys, JSON Web
    Tokens, AWS access key IDs and password hashes (bcrypt, argon2, scrypt,
    SHA-crypt);
  - renders arbitrary values (structs, maps, errors, byte slices) to text before
    scrubbing, so field names such as `DBPassword` are caught.
- Values that must never print are typed `logging.Secret`; their `String`,
  `GoString` and `LogValue` all return `[REDACTED]`. Enrollment tokens use it.
- `TestSecretLeak` logs 24 lines that carry 11 invented secrets in every shape
  above and fails if any secret, or any 12-character fragment of one, appears
  in the output. Every module that logs adds its own secrets to that pattern.
- `FuzzRedactString` checks that redaction never panics and is idempotent.
- The invented secrets live in one file,
  `internal/platform/logging/secrets_fixture_test.go`. It is the only path
  allowlisted in `.gitleaks.toml`; every other file, tests included, is scanned.

## Consequences

- Redaction costs several regular-expression passes per string attribute.
  Hot paths log numbers and IDs, not free text.
- Over-redaction is possible (for example an attribute named `input_token`).
  That is the accepted trade-off.
- Pattern matching is a safety net, not a guarantee; the primary rule remains
  not to put secrets into log calls.
