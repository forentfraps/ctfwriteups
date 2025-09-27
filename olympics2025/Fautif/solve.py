#!/usr/bin/env python3
import argparse
import subprocess
import sys
import re
from math import inf

# Standard printable ASCII: 0x20 (space) to 0x7E (~)
PRINTABLE_ASCII = ''.join(chr(i) for i in range(32, 127))

target = "GGRC{Rot_Tjkyqf_dpzxvg_hha_k_iukaul_cfhghag_izvmg_ehkuexvhsgfkmlgcg_zbeyxmgi_ez_sfqnqcj_klg_brwjfpy_zozngimn!}"


def run_checker(cmd, candidate, timeout):
    """
    Runs the checker once, feeding the candidate via stdin.
    Returns (score, raw_stdout). Extracts the last number found in stdout.
    """
    try:
        completed = subprocess.run(
            cmd,
            input=candidate + "\xff",
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return -inf, f"[TIMEOUT] while checking {candidate!r}"

    out = completed.stdout.strip()
    bts = bytes.fromhex(out)
    xor_key = [bts[0] ^ ord("G"), bts[1] ^ ord("G")]
    dexorred = bytearray()
    for i, bt in enumerate(bts):
        dexorred.append(bt ^ xor_key[i & 1])
    to_check = dexorred.decode("utf-8")
    # print(to_check)
    score = 0
    for c1, c2 in zip(list(to_check), list(target[0:len(to_check)])):
        if (c1 == c2):

            score += 1
        else:
            break
    return score, out

def main():
    ap = argparse.ArgumentParser(description="Position-by-position brute-forcer with score ascent & lock-on-improvement.")
    ap.add_argument("--cmd", required=True, nargs="+",
                    help="Checker command (program and args). Example: --cmd ./checker --flag-mode")
    ap.add_argument("--inner-len", type=int, required=True,
                    help="Number of characters inside the braces, e.g. ASIS{<inner-len chars>}.")
    ap.add_argument("--alphabet", default=PRINTABLE_ASCII,
                    help="Alphabet to try (default: printable ASCII 0x20-0x7E).")
    ap.add_argument("--filler", default="a",
                    help="Filler char for unknown positions (default: 'a').")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="Per-attempt timeout in seconds (default: 5.0).")
    ap.add_argument("--verbose", action="store_true",
                    help="Print each attempt and score.")
    args = ap.parse_args()

    if len(args.filler) != 1:
        print("Filler must be a single character.", file=sys.stderr)
        sys.exit(2)

    # Start with ASIS{aaaa...}
    inner = [args.filler] * args.inner_len

    def build_flag(chars):
        return "ASIS{" + "".join(chars) + "}"

    # Baseline score with initial filler
    current_flag = build_flag(inner)
    best_score, out = run_checker(args.cmd, current_flag, args.timeout)
    if args.verbose:
        print(f"[INIT] {current_flag} -> {best_score} :: {out}")

    # print(f"[BASE] {out} -> {best_score}")

    # For each position, try alphabet until score strictly increases; then lock and move on.
    for pos in range(args.inner_len):
        improved = False
        for ch in args.alphabet:
            trial = inner[:]
            trial[pos] = ch
            trial_flag = build_flag(trial)

            score, out = run_checker(args.cmd, trial_flag, args.timeout)
            if args.verbose:
                print(f"[TRY]  pos={pos} ch={repr(ch)}  {trial_flag} -> {score} :: {out}")

            if score > best_score:
                # Lock this char, update baseline, move to next position
                inner[pos] = ch
                best_score = score
                improved = True
                print(f"[LOCK] pos={pos} char={repr(ch)}  {build_flag(inner)} -> {best_score}")
                break

        if not improved:
            # If no strict improvement was found at this position, optionally pick the best char anyway.
            # This fallback scans all chars again to pick the max-scoring one (may be equal to baseline).
            top_char = None
            top_score = -inf
            for ch in args.alphabet:
                trial = inner[:]
                trial[pos] = ch
                trial_flag = build_flag(trial)
                score, _ = run_checker(args.cmd, trial_flag, args.timeout)
                if score > top_score:
                    top_score = score
                    top_char = ch

            inner[pos] = top_char
            # Only update best_score if it actually improved
            if top_score > best_score:
                best_score = top_score
            print(f"[LOCK*] pos={pos} (no strict improvement found) -> chose {repr(top_char)} | "
                  f"{build_flag(inner)} -> {best_score}")

    final_flag = build_flag(inner)
    print(f"[DONE] {final_flag} -> {best_score}")

if __name__ == "__main__":
    main()
