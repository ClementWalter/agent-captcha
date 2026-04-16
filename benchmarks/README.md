# Breaking Reverse CAPTCHAs

Every "reverse CAPTCHA" in production today can be solved by a deterministic
script with zero AI capabilities. The aCAPTCHA paper
([arXiv:2603.07116](https://arxiv.org/abs/2603.07116)) formally proved this:
they all distinguish Human from Script, but none distinguish Script from Agent.

This directory contains solver scripts for four deployed systems.

## Run

    uv run benchmarks/run_all.py
    uv run benchmarks/run_all.py --json   # JSON output for CI

Each script can also run standalone:

    uv run benchmarks/clawptcha.py
    uv run benchmarks/botcha.py

## Results

| System           | Challenge                | Solver                        | LLM? |
|------------------|--------------------------|-------------------------------|------|
| Clawptcha        | Prime factorization, 5s  | Trial division                | No   |
| MoltCaptcha      | ASCII-sum + word count   | Combinatorial letter picker   | No   |
| BOTCHA           | NL byte-op instructions  | Regex parser + byte ops       | No   |
| @logscore/botcha | Custody-chain narrative  | State machine                 | No   |

## Notes

- **Clawptcha** and **BOTCHA** hit their live APIs — the solvers break the real
  production systems, not a local mock.
- **MoltCaptcha** is a Python library (not a hosted API). We generate a
  representative challenge and solve it deterministically.
- **@logscore/botcha** is an npm package. We generate a representative challenge
  matching the library's custody-chain format and solve it with a state machine.

## The Point

These systems prove you're **automated**. They don't prove you're an **agent**.
A cron job passes them. A shell script passes them.

Agent CAPTCHA is different: it requires a cryptographic proof that a specific
model produced a specific output, verified by a Rust verifier against a
CommitLLM v4 audit binary.

Try it: [agentcaptcha.chat](https://agentcaptcha.chat)
