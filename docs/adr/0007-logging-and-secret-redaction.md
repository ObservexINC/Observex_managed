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
    bound shortens the key that is shown, also when a string key is boxed
    in interfaces or pointers (`map[any]V`); a key made of structs, arrays,
    interfaces or pointers is sensitive when any string in it is. Such a key
    is read within the walk's bounds (below); a key the bounds stop from
    being read in full counts as sensitive, because what was not read
    cannot show that the value is safe. Pointer cycles in a key are read
    once. Keys of an opaque type (`logging.Secret`, `slog.LogValuer`) are
    never read; an opaque part of a key does not make it sensitive.
    Keys that look the same once shortened are shown with " #2", " #3" ...,
    so no entry hides another. Built-in secret words match anywhere in a
    key; names added with `WithSensitiveKeys`, and the short names `pwd`,
    `pass`, `dsn`, `auth`, `jwt` and `bearer`, match only the whole key.
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
    level it follows. Text that is still not valid JSON afterwards may have
    broken quoting (a stray quote shifts every string after it), so it gets
    a second look that does not trust the quoting: from every `:` the
    quoted name before it is read backwards, at the encoding level its
    closing quote shows, decoded and classified, and a sensitive name has
    its value replaced; a name whose opening quote is more than 64 KiB away
    counts as sensitive. Unquoted names before `:` or `=` with an object or
    array value are handled the same way. Where such a value ends is not
    taken from the quoting either: a value with no quote ends where its
    brackets close (when they match); a value holding quotes runs to the
    end of the text that holds it (the whole text, or the JSON string it is
    written in), unless that JSON string is valid JSON on its own. In text
    whose quoting is broken any quote in the value may be an unescaped
    quote of its content, and a cut can remove whatever would show that the
    value goes on, so no reading of the rest can prove where it ends; a
    bracket inside a string therefore never ends a value early. The second
    look has a work budget of a few times the length of the text; text it
    cannot finish within it is replaced as a whole. Valid JSON skips it, so
    its output stays valid JSON; but a string in valid JSON can hold JSON
    whose own quoting is broken, so every string whose content holds
    quotes is decoded and redacted as text of its own, down to three levels
    of encoding, and written back as a JSON string when it changed.
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
