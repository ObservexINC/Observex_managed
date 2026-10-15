# ADR 0008: TLS, identity and enrollment

Status: Proposed. Implements IMP-3 and IMP-4.

## Decision

- Every connection uses TLS 1.3 only, with mutual authentication: servers
  require and verify a client certificate from the cluster CA.
- Key exchange prefers the hybrid post-quantum group X25519MLKEM768, then
  X25519, then P-256. A test proves an ObserveX client completes a handshake
  with a server that accepts only the hybrid group.
- Agents and Gateways enroll with a one-time token `oxe_<id>.<secret>`:
  - the plaintext token is returned once, typed `logging.Secret`;
  - the cluster stores only the ID, a SHA-256 hash of the secret, the expiry
    and a used flag;
  - verification compares in constant time and returns the same error for an
    unknown token, a wrong secret or a malformed token;
  - marking a token used is a compare-and-set in the ConfigurationStore, so two
    concurrent enrollments with one token cannot both succeed (contract test
    "only one concurrent create wins").
- The host generates its private key and sends a certificate signing request;
  the private key never leaves the host.
- Configuration pushed to Agents and Gateways is signed with Ed25519 and is
  refused unless the signature verifies (`config.LoadSigned`).

## Not yet decided

Certificate lifetime and rotation, the CA's key storage (customer KMS or HSM),
and revocation are designed in G04 and G05 with the Gateway and Agent.
