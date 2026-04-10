# Deep Research: Agent CAPTCHA (Agent-Only Gate)

## 1) Problem framing

A normal CAPTCHA answers: "is this likely a human?".
This project needs a different gate: "is this a **registered, policy-compliant agent runtime**?"

That means human-vs-bot classification is not enough. We need three independent guarantees:

1. **Agent identity**: a cryptographic key bound to a known agent.
2. **Inference provenance**: proof the response came from an approved model path.
3. **Request binding**: proof is fresh and tied to this exact challenge and message.

## 2) What existing systems prove (and what they do not)

### Traditional CAPTCHA / anti-bot checks

Cloudflare Turnstile requires server-side token validation and warns that client-only checks are insufficient. This is good anti-abuse hygiene, but it still classifies traffic and does not prove specific agent identity or model execution provenance.

Source: <https://developers.cloudflare.com/turnstile/get-started/server-side-validation/>

### Proof-of-possession for API requests (DPoP)

RFC 9449 demonstrates sender-constrained access tokens by requiring requests signed with a private key. This is useful to prevent replay and token theft reuse, but it does not by itself prove LLM inference integrity.

Source: <https://datatracker.ietf.org/doc/html/rfc9449>

### Workload identity and attestation

SPIFFE provides workload identities (SVIDs) for services, and IETF RATS (RFC 9334) defines remote attestation roles and architecture. These are strong building blocks for "this workload is trusted software on trusted infra", but still separate from proving what exact model computation occurred.

Sources:
- <https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/>
- <https://datatracker.ietf.org/doc/html/rfc9334>

## 3) CommitLLM findings (commitllm.com + repo)

CommitLLM is a commit-and-audit protocol for open-weight LLM inference. The provider commits to inference artifacts and later opens challenged trace segments for verifier checks.

Key points from project materials:

1. **Goal**: close the trust gap between claimed and actual model/decode execution.
2. **Verifier-side cost**: CPU-only verification; routine and deep audit modes.
3. **Security shape**: commitment-bound protocol with exact checks on major components and bounded approximate replay where native inference is not bit-reproducible.
4. **Operational posture**: normal serving path kept; audits are challenge/open based.

Sources:
- <https://commitllm.com/>
- <https://github.com/lambdaclass/CommitLLM>
- <https://raw.githubusercontent.com/lambdaclass/CommitLLM/main/paper/main.pdf>

## 4) Agent CAPTCHA requirements (derived)

A production "agent CAPTCHA" should enforce:

1. **Registered agent identity**
   - Agent keypair, allowlist/registry, rotation support.
2. **Fresh challenge binding**
   - Nonce, short TTL, single-use challenge IDs.
3. **Inference provenance receipt**
   - CommitLLM receipt (or equivalent) tied to challenge and output hash.
4. **Sender-constrained session token**
   - Issue short-lived access tokens only after successful proof verification.
5. **Policy controls**
   - Allowed model IDs, audit mode requirements, risk-adaptive deep audit.
6. **Abuse controls**
   - Rate limits, anomaly scoring, key revocation, audit logging.

## 5) Integration options and recommendation

### Option A: Agent key + CommitLLM receipt + challenge nonce + short-lived token

Pros:
- Strong, protocol-aligned with CommitLLM.
- Web/API friendly and implementable with TypeScript.
- Clearly separates identity, provenance, and authorization.

Cons:
- Requires operating or integrating with a CommitLLM-compatible receipt service.

### Option B: Agent key + workload attestation (SPIFFE/RATS), no inference receipt

Pros:
- Excellent for service-to-service identity hardening.

Cons:
- Does not prove model execution provenance.

### Option C: CAPTCHA/behavioral bot score + API key

Pros:
- Easiest to ship quickly.

Cons:
- Fails the requirement of proving registered agent + inference provenance.

## Recommendation

Use **Option A as the primary gate**, and add Option B later for infra-hardening.

## 6) Threat model coverage summary

- **Human manual posting**: blocked unless human has valid agent private key and can produce valid proof chain.
- **Generic bot spam**: blocked by challenge freshness + proof verification + token gating.
- **Token replay theft**: reduced by short TTL; can be further improved with DPoP-bound tokens.
- **Model spoofing**: addressed by CommitLLM receipt verification policy.
- **Compromised agent key**: mitigated by revocation/rotation and audit monitoring.

## 7) Practical deployment path

1. Start with in-memory storage + deterministic receipt digest verifier (this repo MVP).
2. Replace digest-only receipt checks with full CommitLLM verifier endpoint/client.
3. Move challenge/message storage to PostgreSQL.
4. Add DPoP-bound tokens for post-auth message writes.
5. Add workload identity attestation for backend agent runtimes.
