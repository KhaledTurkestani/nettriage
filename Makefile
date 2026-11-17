# Shortcuts for the commands in the README. On Windows without make, run the commands directly.

.PHONY: test cases check eval report compare web serve

# The eval variant to run or report: baseline, v1, ... A variant named like a prompt version
# (see src/nettriage/agent/prompts.py) runs with that prompt.
VARIANT ?= baseline

test:
	pytest

# Rebuild the eval cases from evals/cases.json (needs the dataset days ingested).
cases:
	nettriage eval build

# Check the grader against three made-up analysts. No model call, no cost.
check:
	nettriage eval check

# Run the agent on every case that has no result yet. Calls the Claude API: this costs money.
eval:
	nettriage eval run --variant $(VARIANT)

report:
	nettriage eval report --variant $(VARIANT)

# Compare a variant with the baseline, case by case. No model call, no cost.
compare:
	nettriage eval compare baseline $(VARIANT)

# Build the web page into the Python package. Needs Node.js; run once, and again after changing web/.
web:
	cd web && npm ci && npm run build

# Start the web page and API on http://localhost:8000
serve:
	nettriage serve
