# ADR 0007: Logging and secret redaction

Status: Proposed. Implements akash's standing rule: never log, print or send
any secret value or fragment.

## Decision

- Every process logs through `logging.NewHandler`, a `log/slog` handler that
  redacts in three layers:
  - **Keys.** An attribute, struct field (or its JSON name), map key, JSON
    member or group whose name says it holds a secret (password, token,
    secret, API key, private key, credential, creds, authorization, cookie,
    DSN and similar, after normalising case and separators) has its whole
    value replaced, whatever the value's type. A group opened with
    `WithGroup("credentials")` redacts everything below it, exactly as
    `slog.Group("credentials", ...)` does.
  - **Structure.** Arbitrary values (structs, maps, slices, pointers) are
    walked by reflection before anything becomes text, so `DBPassword` in a
    struct is dropped before rendering instead of being searched for in the
    rendered text. The walk is bounded (depth 8, 256 items per collection,
    4096 values, 64 KiB per string) and marks cycles and truncation. Only
    `LogValue`, `Error` and, for enumerations (named numbers and booleans),
    `String` are called, each under `recover`: a panic logs
    `[UNPRINTABLE]`, never a stack trace. Other `String` methods are not
    called, since one could print a secret field. A string that is a whole
    JSON object or array (up to 1 MiB) is parsed and redacted member by
    member.
  - **Text.** Message text, string values and error messages are scrubbed
    for credentials in URLs and DSNs, bearer and basic credentials,
    key=value secrets, PEM private keys, JSON Web Tokens, AWS access key IDs
    and password hashes (bcrypt, argon2, scrypt, SHA-crypt). Quoted values
    are matched escape-aware (`\"` does not end a value, double-encoded JSON
    included), and a value whose closing quote never comes is redacted to
    the end of the text.
- Output of child processes (NGINX and, later, the other components) passes
  through the Node Supervisor's line filter: each line is redacted with the
  text rules, and a multi-line PEM private key is followed across lines and
  writes. From its `BEGIN ... PRIVATE KEY` marker to its `END` marker every
  line is dropped; a key whose `END` never comes is dropped until the process
  exits (fail closed).
- Values that must never print are typed `logging.Secret`; their `String`,
  `GoString` and `LogValue` all return `[REDACTED]`. Enrollment tokens use it.
- `TestSecretLeak` logs 24 lines that carry 11 invented secrets in every shape
  above and fails if any secret, or any 12-character fragment of one, appears
  in the output. Every module that logs adds its own secrets to that pattern.
- `FuzzRedactString` checks that redaction never panics and is idempotent;
  `FuzzRedactConfidential` puts a marker secret into every key, quoting and
  escaping shape and fails if it survives; `FuzzPrefixWriter` cuts PEM keys
  into arbitrary writes and fails if key material reaches the output.
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
