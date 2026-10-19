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
    `slog.Group("credentials", ...)` does. Map keys and member names are
    classified on their full original text, before redaction or the 64 KiB
    bound shortens the key that is shown; keys that look the same once
    shortened are shown with " #2", " #3" ..., so no entry hides another.
  - **Types.** A `logging.Secret` is `[REDACTED]` wherever it is found:
    behind pointers and interfaces, in collections, and in unexported
    fields, where reflection could otherwise read the string under it. The
    type decides, so nothing is read. A value in an unexported field whose
    type defines its own log form (`slog.LogValuer`) cannot be asked for it
    there, so it is `[REDACTED]` too rather than walked.
  - **Structure.** Arbitrary values (structs, maps, slices, pointers) are
    walked by reflection before anything becomes text, so `DBPassword` in a
    struct is dropped before rendering instead of being searched for in the
    rendered text. The walk is bounded (depth 8, 256 items per collection,
    4096 values, 64 KiB per string) and marks cycles and truncation. Only
    `LogValue`, `Error` and, for enumerations (named numbers and booleans),
    `String` are called, each under `recover`: a panic logs
    `[UNPRINTABLE]`, never a stack trace. Other `String` methods are not
    called, since one could print a secret field. A string that is a whole
    JSON object or array of at most 1 MiB is parsed and redacted member by
    member. Any other text (larger, truncated or malformed JSON, JSON inside
    other text, and JSON written into JSON strings, up to three levels) gets
    a structural pass that replaces the whole value of every member with a
    sensitive name: string, number, object or array, and to the end of its
    text when it never closes. Names are decoded (`\u` escapes included)
    before they are classified. The pass is linear in the text for each
    level it follows.
  - **Text.** Message text, string values and error messages are scrubbed
    for credentials in URLs and DSNs, bearer and basic credentials,
    key=value secrets, PEM private keys, JSON Web Tokens, AWS access key IDs
    and password hashes (bcrypt, argon2, scrypt, SHA-crypt). Quoted values
    are matched escape-aware (`\"` does not end a value, double-encoded JSON
    included), and a value whose closing quote never comes is redacted to
    the end of the text. A quoted value keeps its quotes
    (`"password":"[REDACTED]"`), so JSON-like text stays JSON-like.
- Work limits fail closed: text longer than 8 MiB (`MaxRedactInput`) is not
  examined but replaced as a whole by `[REDACTED]` and its length. Reaching
  a limit never lowers the protection.
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
  escaping shape and fails if it survives; `FuzzSensitiveShapes` builds what
  random short strings rarely reach (secret types behind pointers,
  interfaces and unexported fields, keys around 64 KiB, JSON around 1 MiB,
  nested, escaped, cut short or double-encoded) and fails if a marker
  survives; `FuzzPairsMatchExpression` checks that the key=value scan gives
  exactly what the single regular expression it replaced gave;
  `FuzzPrefixWriter` cuts PEM keys into arbitrary writes and fails if key
  material reaches the output.
- The invented secrets live in one file,
  `internal/platform/logging/secrets_fixture_test.go`. It is the only path
  allowlisted in `.gitleaks.toml`; every other file, tests included, is scanned.

## Consequences

- Redaction costs a structural pass and several regular-expression passes
  per string attribute; expressions that cannot match (none of their
  literals occurs) are skipped. Hot paths log numbers and IDs, not free
  text. A 1 MiB string takes tens of milliseconds.
- Over-redaction is possible (for example an attribute named `input_token`).
  That is the accepted trade-off.
- Pattern matching is a safety net, not a guarantee; the primary rule remains
  not to put secrets into log calls.
