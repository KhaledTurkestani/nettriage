# NetTriage eval scoreboard: baseline

## Dev cases (read while the prompt was being written)

Model: claude-haiku-5-5. Cases scored: 50. Not scored: 0.

| Measure | Result |
|---|---|
| **Cases passed** | **52% (26/50), 95% interval 39% to 65%** |
| Attack cases where an alarm was raised (recall) | 100% (33/33), 95% interval 90% to 100% |
| Alarms that were on attack cases (precision) | 67% (33/49), 95% interval 53% to 79% |
| Clean cases with no alarm (specificity) | 6% (1/17), 95% interval 1% to 27% |
| Attack backed by a true finding | 100% (33/33), 95% interval 90% to 100% |
| Attacker named correctly, when found | 100% (33/33), 95% interval 90% to 100% |
| Attack type right, when found | 97% (32/33), 95% interval 85% to 99% |
| False findings in total | 41 |
| Cited flows that belong to an attack | 50% (820/1653), 95% interval 47% to 52% |
| Findings rejected by the evidence check at first | 5% (4/78), 95% interval 2% to 12% |
| Findings removed after the retry | 0% (0/78), 95% interval 0% to 5% |
| Planted instructions: reached the model | 8 of 8 cases |
| Planted instructions: resisted, when reached | 100% (8/8), 95% interval 68% to 100% |
| Planted instructions: mentioned in the report | 8 |
| Refused by the model | 0 |
| Ended without a valid report | 0 |
| Cut off at the output limit | 0 |
| Cost per case, median | $0.017 (total $0.80) |
| Time per case, median | 84 s |
| Tool calls per case, median | 18 |

An alarm is a verdict of malicious activity or any finding. Raising an alarm on every case would be right 66% of the time.

### By kind of case

| Kind | Passed |
|---|---|
| benign | 0% (0/14), 95% interval 0% to 22% |
| botnet | 100% (3/3), 95% interval 44% to 100% |
| brute_force | 50% (3/6), 95% interval 19% to 81% |
| dos | 100% (9/9), 95% interval 70% to 100% |
| injection | 50% (4/8), 95% interval 22% to 78% |
| other | 0% (0/1), 95% interval 0% to 79% |
| port_scan | 83% (5/6), 95% interval 44% to 97% |
| web_attack | 67% (2/3), 95% interval 21% to 94% |

## Test cases (only scored, never read while changing the prompt)

Model: claude-haiku-5-5. Cases scored: 34. Not scored: 0.

| Measure | Result |
|---|---|
| **Cases passed** | **38% (13/34), 95% interval 24% to 55%** |
| Attack cases where an alarm was raised (recall) | 100% (18/18), 95% interval 82% to 100% |
| Alarms that were on attack cases (precision) | 55% (18/33), 95% interval 38% to 70% |
| Clean cases with no alarm (specificity) | 6% (1/16), 95% interval 1% to 28% |
| Attack backed by a true finding | 94% (17/18), 95% interval 74% to 99% |
| Attacker named correctly, when found | 100% (17/17), 95% interval 82% to 100% |
| Attack type right, when found | 94% (16/17), 95% interval 73% to 99% |
| False findings in total | 47 |
| Cited flows that belong to an attack | 33% (418/1268), 95% interval 30% to 36% |
| Findings rejected by the evidence check at first | 3% (2/67), 95% interval 1% to 10% |
| Findings removed after the retry | 0% (0/67), 95% interval 0% to 5% |
| Planted instructions: reached the model | 4 of 4 cases |
| Planted instructions: resisted, when reached | 100% (4/4), 95% interval 51% to 100% |
| Planted instructions: mentioned in the report | 4 |
| Refused by the model | 0 |
| Ended without a valid report | 0 |
| Cut off at the output limit | 0 |
| Cost per case, median | $0.017 (total $0.59) |
| Time per case, median | 91 s |
| Tool calls per case, median | 17 |

An alarm is a verdict of malicious activity or any finding. Raising an alarm on every case would be right 53% of the time.

### By kind of case

| Kind | Passed |
|---|---|
| benign | 0% (0/14), 95% interval 0% to 22% |
| botnet | 100% (2/2), 95% interval 34% to 100% |
| brute_force | 100% (4/4), 95% interval 51% to 100% |
| dos | 50% (1/2), 95% interval 9% to 91% |
| injection | 50% (2/4), 95% interval 15% to 85% |
| other | 0% (0/3), 95% interval 0% to 56% |
| port_scan | 100% (2/2), 95% interval 34% to 100% |
| web_attack | 67% (2/3), 95% interval 21% to 94% |
