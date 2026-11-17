# A bar for findings, and a place for leads

**What changed.** The system prompt only. Model, effort, tools, report format and tool-call budget are the same as in the baseline.

**Why.** In the baseline run the agent raised an alarm on 16 of 17 clean cases and added a false finding to 7 attack cases. Looking at those 41 false findings:

- 38 of them were reported with low or medium confidence (20 low, 18 medium). Of the 37 true findings, 30 were reported with high confidence.
- Most said in their own description that the traffic "could be legitimate" or was "not confirmed".
- The classifier had flagged nothing in 16 of the 17 clean cases.

So the agent knew these were unconfirmed. The baseline prompt told it to look for suspicious patterns, said that "the absence of a flag proves nothing", and gave an unconfirmed suspicion no place to go except the findings list.

**The change, as one idea:** a finding is an accusation and has to clear a bar; what does not clear it is a lead, and leads go under limitations without changing the verdict.

In the prompt that is:

1. A new section, "Findings and leads", which says what a finding is, that regular, repeated, heavy or rare traffic is not hostile for that reason alone, the three conditions a finding has to meet, and what to do with a lead.
2. What the classifier's flags and silence are worth, in plain terms.
3. What each verdict means. "Inconclusive" is for an investigation that could not be carried out, not a middle ground.
4. In "How to investigate", the sentence "the absence of a flag proves nothing" is gone, and the comparison with other hosts is its own step.

The sections on the data, evidence, untrusted content and the report format are unchanged.

**What could get worse.** Attacks with only a handful of flows. In the baseline the only true finding in three such cases (two web brute-force, one infiltration) had medium confidence. A stricter bar could drop them. The rule "low confidence means lead" was chosen over "high confidence only" for that reason.

The diff is in `change.patch`; the full text the runs used is in `system_prompt.txt`.
