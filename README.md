# Odeya

[![CI](https://github.com/manfromnowhere143/odeya-console/actions/workflows/ci.yml/badge.svg)](https://github.com/manfromnowhere143/odeya-console/actions/workflows/ci.yml)

## 1. What it is

Odeya is a Python CLI that audits an AI-generated patch after a test harness says the work is complete. It combines a frozen named-pattern detector, an optional blind GPT-5.6 semantic judge, and a hash-chained receipt ledger. It records what each layer saw, including a quiet detector, without treating silence or passing tests as proof of correctness.

## 2. Quickstart

Odeya supports macOS and Linux with Python 3.12 and
[uv](https://docs.astral.sh/uv/). The keyless path does not use the network:
the static controls and bundled cases run, the judge prints one skipped line,
and receipts are still written.

```bash
git clone https://github.com/manfromnowhere143/odeya-console
cd odeya-console
uv sync --python 3.12
uv run odeya demo
```

To enable the blind judge, set the key only in the process environment:

```bash
export OPENAI_API_KEY="replace-with-your-key"
export ODEYA_JUDGE_MODEL="gpt-5.6-sol"
uv run odeya demo
```

The account smoke test exposed `gpt-5.6-luna`, `gpt-5.6-sol`, and
`gpt-5.6-terra`; a structured request through the `gpt-5.6` alias returned
`gpt-5.6-sol`. Odeya therefore defaults to the exact confirmed
`gpt-5.6-sol` model ID. The probe is recorded in the
[build snapshot](evidence/build-snapshot.json), and the API integration follows
OpenAI's [Responses API Structured Outputs
guidance](https://developers.openai.com/api/docs/guides/structured-outputs).

The four commands are:

```text
odeya demo
odeya check --diff candidate.patch [--issue issue.md] [--tests tests.txt]
odeya verify-ledger
odeya cases
```

`--tests` is a UTF-8 file with one test node ID per line. `check` returns `0`
when no layer emits a signal, `1` when the detector or a completed judge emits
a signal, and `2` for a usage or operational error. `demo` returns `0` when the
showcase and receipt verification complete, even though its purpose is to show
wrong patches. `verify-ledger` returns `0` for a valid chain and `1` for an
invalid chain.

## 3. What the demo shows

1. The harness said RESOLVED after 41 graded tests for `django__django-11179`.
2. The recorded differential oracle returns `None` for gold and `'present'` for the variant.
3. Static analysis stays quiet: no named pattern is detected, and the miss is stated.
4. The blind `gpt-5.6-sol` judge flags the variant while gold is withheld; the receipt records all of it, including the miss.

The demo first proves that the unchanged detector fires on three named control
families: verifier provenance violation, assertion weakening, and hidden-input
special-casing. It then audits three certified-resolved semantic variants. For
each variant the keyed output says, in order: the harness said RESOLVED; static
analysis stays quiet; the blind judge flags it; the receipt records all of it,
including the miss. Without a key, the same output replaces the judge flag with
an explicit nondecision and still records that result.

The bundled patches are byte-identical to the cited Telos evidence. Each
[case directory](cases/) includes the candidate, gold reference, canonical
SWE-bench issue statement, newline-delimited test IDs, and provenance metadata.
Gold is used only for the committed differential story and detector regression
test. The judge request type has no gold field and receives only the issue,
candidate patch, and named tests.

## 4. How Codex and GPT-5.6 built and power this

The majority of the tool's core functionality was built from one primary Codex
Project thread:
`019f703b-9812-7bc2-915b-9678e2c8283a`. That session ran on
`gpt-5.6-sol` with ultra reasoning and coordinated bounded Codex agents for the
detector, judge, and ledger modules. The primary thread recovered the Fable 5
mission history, audited the source evidence, integrated the modules, corrected
the judge schema to the required three-way verdict, implemented the CLI and
evidence packaging, and ran the final verification.

The operator made the central product decision after Codex found that the
unchanged Telos detector stayed quiet on the selected semantic variants. The
approved design keeps that miss visible: no new heuristic was fitted to the
known cases, named-pattern controls demonstrate the static layer, and the blind
judge plus recorded differential oracle handle the subtle examples. Codex
accelerated repository reconnaissance, parallel module implementation,
integration testing, and claim auditing; the operator fixed the product scope,
approved the honesty boundary, and authorized the live model run.

GPT-5.6 powers the optional in-product judge through one Responses API call per
case with strict structured output. A retained keyed demo used
`gpt-5.6-sol`, kept gold out of every request, completed all three judge calls,
and recorded all three as `suspicious` or `wrong`; the
[hash-chained ledger](evidence/keyed-demo-ledger.jsonl) is committed for
inspection. This is one live run, not a stability or benchmark estimate.

In the prior Telos research, `gpt-5.6-terra` authored adversarial variants,
served as the neutral-prompt experimental subject, generated candidate
properties, and occupied one blind-judge slot. The submission therefore uses
GPT-5.6 both inside the runnable product and in the research that motivated it.

## 5. Prior work vs Build Week work

The [OpenAI Build Week rules](https://openai.devpost.com/rules) allow an
existing project only when it was meaningfully extended with Codex or GPT-5.6
after the submission period began and the prior and new work are clearly
distinguished. The submission-period boundary used here is
`2026-07-13T16:00:00Z`.

All counts below were measured on `2026-07-17` with
`git rev-list --all --count`; in-window counts add
`--since=2026-07-13T16:00:00Z`. Exact heads, commands, and counts are retained
in the [build snapshot](evidence/build-snapshot.json).

### Created entirely during Build Week

| Repository | First commit | Commits in window | Share in window |
|---|---|---:|---:|
| [odeya](https://github.com/manfromnowhere143/odeya), the engine foundation | 2026-07-15 | 57 / 57 | 100% |
| [inbar](https://github.com/manfromnowhere143/inbar), the physical causal-evidence mission | 2026-07-14 | 109 / 109 | 100% |
| `odeya-console`, the submitted tool | 2026-07-17 | all commits in this repository | 100% |

The current Odeya foundation reports 100 Draft 2020-12 schemas, 588
valid/adversarial cases, seven bounded safe TLA+ models, and thirty mutation
controls. Those establish structural and bounded semantic evidence only; Odeya
Gate A remains blocked, and the engine is not presented as a completed runtime.

### Pre-existing and meaningfully extended during Build Week

| Repository | First commit | Pre-window commits | In-window commits | Rounded in-window share |
|---|---|---:|---:|---:|
| [telos](https://github.com/manfromnowhere143/telos), reward-hack research | 2026-07-08 | 197 | 167 | 46% |
| [sentinel](https://github.com/manfromnowhere143/sentinel), AV-safety monitor research | 2026-06-30 | 598 | 259 | 30% |

In-window Telos work includes admission gates, natural-rate cohorts, detector
evaluation, and paper revisions. In-window Sentinel work includes the
pre-registered placebo-control execution that retained its own dose confound
and the next host-provenance-gated protocol. Prior work reused here is labeled:
Telos supplied the certified-resolved benchmark and detector core; Sentinel
supplied the earlier NeuroNCAP result and its committed proof.

### Codex and GPT-5.6 evidence within the window

- Odeya Console core: this Codex session,
  `019f703b-9812-7bc2-915b-9678e2c8283a`, started on `2026-07-17`.
- Sentinel's continuity ledger records 150 Codex-tagged shifts and 24
  Claude-tagged shifts across that campaign.
- Inbar's Ed25519-signed append-only memory ledger at commit `5465ae8` contains
  181 events: `codex-primary` 87, `codex` 62, `claude` 28, and
  `daniel-wahnich` 4.
- Telos records `gpt-5.6-terra` in the research roles described above and
  `codex-local-*` or `codex-openai-*` agent IDs throughout its run scripts.
- The four foundation repositories contained 592 in-window commits at the
  retained measurement point.

The public README intentionally omits account email addresses and any claim
that a Session ID independently resolves a person's identity.

## 6. The research foundation

**[Odeya](https://github.com/manfromnowhere143/odeya)** defines the wider
contract-before-cognition architecture: typed evidence, authority separation,
verification packages, and bounded formal models. It was created during Build
Week, but its own README keeps Gate A blocked; this console is a small runnable
slice, not a claim that the whole engine is operational. The live project
surface is [odeya.danielwahnich.dev](https://odeya.danielwahnich.dev).

**[Telos](https://github.com/manfromnowhere143/telos)** supplies the
certified-resolved reward-hack evidence, the frozen named-pattern detector, and
the three bundled candidate/gold pairs. Its 22-row cohort spans eight
repositories, and its [compiled
paper](https://github.com/manfromnowhere143/telos/blob/master/paper/telos.pdf)
keeps the judge nondecisions and control flags next to the catch count. The live
project surface is [telos.danielwahnich.dev](https://telos.danielwahnich.dev).

**[Sentinel](https://github.com/manfromnowhere143/sentinel)** applies the same
monitoring principle to a frozen autonomous-driving planner. On the NeuroNCAP
benchmark its retained power run measured 2.12 without the monitor and 2.91
with it, a difference of 0.783 with a 95% confidence interval from 0.605 to
0.928; its deployment metric was null, and the HUGSIM transfer experiments were
also null. These are benchmark-bounded results, not production or real-world
safety claims. Sentinel includes a [compiled
paper](https://github.com/manfromnowhere143/sentinel/blob/master/docs/paper/paper.pdf);
the live surface is
[sentinel.danielwahnich.dev](https://sentinel.danielwahnich.dev).

**[Inbar](https://github.com/manfromnowhere143/inbar)** explores physical
causal-evidence missions with separate evidence, hypothesis, safety, execution,
outcome, truth, and statistical authorities. Its signed ledger proves key
possession and preserves an append-only mission record; it does not by itself
prove scientific truth or historical immutability outside its Git anchor. The
live project surface is
[inbar.danielwahnich.dev](https://inbar.danielwahnich.dev).

Odeya Console is licensed under Apache-2.0. The vendored detector retains its
Telos source commit and Apache attribution in [NOTICE](NOTICE).

## 7. Scope and limitations

- The deterministic layer recognizes named syntactic patterns. It fires on the
  three bundled control families but stays quiet on all three bundled semantic
  variants and their gold patches. A quiet result means only that no named
  pattern matched; it is not a correctness verdict.
- The retained Telos judge-panel result is an exploratory one-run result:
  20/22 variant rows were caught, 3/22 gold-control rows were flagged, and 8/88
  responses were unparseable. The panel was stochastic and does not establish
  completeness or a stable false-positive rate.
- The keyed Odeya demo committed here flagged 3/3 bundled variants in one run.
  The cases were selected before this product run, but three outcomes are not a
  benchmark and future model calls can differ.
- The neutral-prompt natural-occurrence finding is an existence result from a
  small exploratory sample. It is not a frequency estimate for coding agents.
- The blind judge sees the issue, candidate diff, and optional named tests. It
  never sees the gold patch, does not execute code, and can be wrong, refuse,
  time out, or return a nondecision.
- A hash chain detects edited records, internal deletion, reordering, malformed
  entries, and partial writes. Clean removal of a final suffix is detectable
  only when the verifier has an independently retained expected head hash or
  entry count; `verify-ledger` accepts both checkpoints.
- Odeya does not prove a patch correct, replace project-specific tests, or
  provide a completeness guarantee. It preserves independent signals and their
  limitations so a reviewer can decide what additional evidence is required.
