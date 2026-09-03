#!/usr/bin/env bash
# Regenerates docs/media/demo.gif. Runs entirely against the committed fixture,
# whose account ID is already scrubbed to the documentation account, so nothing
# real reaches the recording.
#
#   asciinema rec docs/media/demo.cast --window-size 100x32 --overwrite \
#       --command docs/media/record-demo.sh --title iam-replay
#   agg --theme asciinema --font-size 15 --line-height 1.35 --speed 1.15 \
#       --idle-time-limit 1.4 --last-frame-duration 4 \
#       docs/media/demo.cast docs/media/demo.gif
set -u
export COLUMNS=100
export FORCE_COLOR=1
export TERM=xterm-256color
cd "$(git rev-parse --show-toplevel)"
export PATH="$PWD/.venv/bin:$PATH"
EV=tests/fixtures/cloudtrail/live/workload_events.json
ROLE=arn:aws:iam::123456789012:role/iam-replay-fixture-workload
P='\033[1;32m❯\033[0m'
D='\033[2m'; R='\033[0m'

say() { printf "${D}# %s${R}\n" "$1"; sleep 1.6; }
cmd() { printf "$P %s\n" "$1"; sleep 1.0; }

clear; sleep 0.6
say "A deploy role, and a policy you are about to tighten."
say "First: replay its real CloudTrail history against the policy in force."
cmd "iam-replay --principal .../DeployRole --policy in-force.json --source files ..."
iam-replay --principal "$ROLE" --policy tests/fixtures/cloudtrail/live/policy-tight-baseline.json \
  --source files --path $EV --days 3650 2>/dev/null | sed -n '2,13p;/WOULD DENY/,+1p'
sleep 3.5

say "Nothing breaks. Now the tightened candidate."
cmd "iam-replay --principal .../DeployRole --policy candidate.json --source files ..."
iam-replay --principal "$ROLE" --policy tests/fixtures/cloudtrail/live/policy-candidate.json \
  --source files --path $EV --days 3650 2>/dev/null | sed -n '/WOULD DENY/,/^NEW ACCESS/p' | sed '$d'
sleep 4.5

say "Two calls break outright. Three more it refuses to guess at, and says why."
say "A wrong ALLOW breaks production. A wrong DENY destroys trust in the report."
say "Both are worse than an honest INDETERMINATE."
sleep 2.5
