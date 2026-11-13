"""
Runs the full experiment for ONE model.

Usage:
  python run_all.py <backend>
  e.g. python run_all.py groq-qwen

Plan per model: every scenario in scenarios/ (except the optional shared-doc pair):
  PHISH_RUNS runs of each phishing file,
  CONTROL_RUNS runs of each fake-login-page (V1) normal file,
  EMAIL_CONTROL_RUNS runs of each fake-email (V2) normal file. The four V2 normal
  files contain the same email, so 4 x 5 = 20 runs act as one control with 20 runs.
  Total per model: 8 x 20 + 4 x 20 + 4 x 5 = 260 runs.
Runs go round by round (all files once, then all again, ...), so if the daily limit
stops it halfway, every combination has about the same number of runs.

Safe to stop (Ctrl+C) and start again: finished runs are skipped,
a half-finished run is deleted and redone.
If the provider's limit is hit, it stops; run the same command again later.
"""

import glob
import json
import os
import sys

import agent

PHISH_RUNS = 20
CONTROL_RUNS = 20         # V1 normal files (fake login page controls)
EMAIL_CONTROL_RUNS = 5    # V2 normal files (the shared email control)
SKIP_STORYLINES = {"shared_doc"}  # the optional extra pair: not part of the main runs


def last_line(path):
    with open(path) as f:
        lines = f.readlines()
    return json.loads(lines[-1]) if lines else None


def is_finished(run_id):
    path = os.path.join("logs", f"{run_id}.jsonl")
    if not os.path.exists(path):
        return False
    end = last_line(path)
    return bool(end) and end["tool"] == "run_end"


def remove_run(run_id):
    for name in (f"{run_id}.jsonl", f"{run_id}.transcript.json"):
        path = os.path.join("logs", name)
        if os.path.exists(path):
            os.remove(path)


def runs_wanted(s, name):
    """How many runs this scenario file gets."""
    is_phish = s.get("condition") == "phishing" or (
        "condition" not in s and "phish" in name)
    if is_phish:
        return PHISH_RUNS
    if s.get("vector") == "V2":
        return EMAIL_CONTROL_RUNS
    return CONTROL_RUNS


def main(backend):
    if backend not in agent.BACKENDS:
        sys.exit(f"Unknown backend '{backend}'. Choose one of: {', '.join(agent.BACKENDS)}")

    # Which scenarios to run, and how often
    scenarios = []
    for path in sorted(glob.glob(os.path.join("scenarios", "*.json"))):
        with open(path) as f:
            s = json.load(f)
        if s.get("storyline") in SKIP_STORYLINES:
            continue
        name = os.path.splitext(os.path.basename(path))[0]
        scenarios.append((path, name, runs_wanted(s, name)))

    # The plan: round 1 = every file once, round 2 = every file again, ...
    rounds = max(wanted for _, _, wanted in scenarios)
    plan = [(path, name, rnd)
            for rnd in range(1, rounds + 1)
            for path, name, wanted in scenarios
            if rnd <= wanted]

    def done_count():
        return sum(is_finished(f"{backend}__{name}__r{rnd}") for _, name, rnd in plan)

    print(f"{backend}: {len(scenarios)} scenario files, {len(plan)} runs planned, "
          f"{done_count()} already finished.")

    for path, name, rnd in plan:
        run_id = f"{backend}__{name}__r{rnd}"  # e.g. groq-qwen__11_otp_phish__r1
        log_path = os.path.join("logs", f"{run_id}.jsonl")

        # Already done? Skip. Half-done (no run_end line)? Delete and redo.
        if is_finished(run_id):
            continue
        remove_run(run_id)

        # Each round gets its own OTP seed, the same for every model (fair comparison).
        agent.run(path, backend, run_id, otp_seed=rnd)

        end = last_line(log_path) if os.path.exists(log_path) else None
        reason = end["args"]["reason"] if end and end["tool"] == "run_end" else ""
        if "RateLimit" in reason:
            # Hit the provider's limit: this run doesn't count. Remove it so it's redone next time.
            remove_run(run_id)
            print(f"\nLimit reached: {done_count()} of {len(plan)} runs finished. "
                  f"Run 'python run_all.py {backend}' again later to continue.")
            return

    print(f"\nDone: {done_count()} of {len(plan)} runs finished for {backend}.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])