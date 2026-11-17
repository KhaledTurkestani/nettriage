# NetTriage eval scoreboard: v1

## Dev cases (read while the prompt was being written)

Model: claude-haiku-5-5. Cases scored: 50. Not scored: 0.

| Measure | Result |
|---|---|
| **Cases passed** | **88% (44/50), 95% interval 76% to 94%** |
| Attack cases where an alarm was raised (recall) | 100% (33/33), 95% interval 90% to 100% |
| Alarms that were on attack cases (precision) | 89% (33/37), 95% interval 75% to 96% |
| Clean cases with no alarm (specificity) | 76% (13/17), 95% interval 53% to 90% |
| Attack backed by a true finding | 97% (32/33), 95% interval 85% to 99% |
| Attacker named correctly, when found | 100% (32/32), 95% interval 89% to 100% |
| Attack type right, when found | 97% (31/32), 95% interval 84% to 99% |
| False findings in total | 6 |
| Cited flows that belong to an attack | 73% (793/1079), 95% interval 71% to 76% |
| Findings rejected by the evidence check at first | 3% (1/38), 95% interval 0% to 14% |
| Findings removed after the retry | 0% (0/38), 95% interval 0% to 9% |
| Planted instructions: reached the model | 8 of 8 cases |
| Planted instructions: resisted, when reached | 100% (8/8), 95% interval 68% to 100% |
| Planted instructions: mentioned in the report | 8 |
| Refused by the model | 0 |
| Ended without a valid report | 0 |
| Cut off at the output limit | 0 |
| Cost per case, median | $0.013 (total $0.75) |
| Time per case, median | 71 s |
| Tool calls per case, median | 16 |

An alarm is a verdict of malicious activity or any finding. Raising an alarm on every case would be right 66% of the time.

### By kind of case

| Kind | Passed |
|---|---|
| benign | 71% (10/14), 95% interval 45% to 88% |
| botnet | 100% (3/3), 95% interval 44% to 100% |
| brute_force | 83% (5/6), 95% interval 44% to 97% |
| dos | 89% (8/9), 95% interval 56% to 98% |
| injection | 100% (8/8), 95% interval 68% to 100% |
| other | 100% (1/1), 95% interval 21% to 100% |
| port_scan | 100% (6/6), 95% interval 61% to 100% |
| web_attack | 100% (3/3), 95% interval 44% to 100% |

## Test cases (only scored, never read while changing the prompt)

Model: claude-haiku-5-5. Cases scored: 34. Not scored: 0.

| Measure | Result |
|---|---|
| **Cases passed** | **94% (32/34), 95% interval 81% to 98%** |
| Attack cases where an alarm was raised (recall) | 100% (18/18), 95% interval 82% to 100% |
| Alarms that were on attack cases (precision) | 95% (18/19), 95% interval 75% to 99% |
| Clean cases with no alarm (specificity) | 94% (15/16), 95% interval 72% to 99% |
| Attack backed by a true finding | 94% (17/18), 95% interval 74% to 99% |
| Attacker named correctly, when found | 100% (17/17), 95% interval 82% to 100% |
| Attack type right, when found | 100% (17/17), 95% interval 82% to 100% |
| False findings in total | 2 |
| Cited flows that belong to an attack | 79% (370/470), 95% interval 75% to 82% |
| Findings rejected by the evidence check at first | 0% (0/19), 95% interval 0% to 17% |
| Findings removed after the retry | 0% (0/19), 95% interval 0% to 17% |
| Planted instructions: reached the model | 4 of 4 cases |
| Planted instructions: resisted, when reached | 100% (4/4), 95% interval 51% to 100% |
| Planted instructions: mentioned in the report | 4 |
| Refused by the model | 0 |
| Ended without a valid report | 0 |
| Cut off at the output limit | 0 |
| Cost per case, median | $0.014 (total $0.55) |
| Time per case, median | 79 s |
| Tool calls per case, median | 17 |

An alarm is a verdict of malicious activity or any finding. Raising an alarm on every case would be right 53% of the time.

### By kind of case

| Kind | Passed |
|---|---|
| benign | 93% (13/14), 95% interval 69% to 99% |
| botnet | 100% (2/2), 95% interval 34% to 100% |
| brute_force | 100% (4/4), 95% interval 51% to 100% |
| dos | 100% (2/2), 95% interval 34% to 100% |
| injection | 100% (4/4), 95% interval 51% to 100% |
| other | 67% (2/3), 95% interval 21% to 94% |
| port_scan | 100% (2/2), 95% interval 34% to 100% |
| web_attack | 100% (3/3), 95% interval 44% to 100% |
