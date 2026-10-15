package logging

// This file holds only invented secrets used as test fixtures. It is the one
// path allowlisted in .gitleaks.toml, so keep anything else out of it.

// The secrets below are invented for tests. The leak test fails if any of
// them, or any long fragment of them, reaches the log output.
const (
	pwSecret     = "Hunter2-Correct-Horse"
	tokenSecret  = "tkn_9f8e7d6c5b4a39281706"
	dsnSecret    = "S3cretDbPassw0rd"
	bearerSecret = "abcDEF123ghiJKL456mnoPQR789"
	awsKeyID     = "AKIAIOSFODNN7EXAMPLE"
	jwtSecret    = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvYnNlcnZleCJ9.c2lnbmF0dXJlLXZhbHVl"
	bcryptHash   = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
	argonHash    = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
	pemKeyBody   = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
	extraSecret  = "license-0123456789"
	typedSecret  = "typed-secret-value-42"
)

var allSecrets = []string{
	pwSecret, tokenSecret, dsnSecret, bearerSecret, awsKeyID, jwtSecret,
	bcryptHash, argonHash, pemKeyBody, extraSecret, typedSecret,
}
