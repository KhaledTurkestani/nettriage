# NetTriage

An AI agent that investigates network traffic like a SOC analyst. It queries
flows through read-only tools, calls an ML classifier to flag suspicious
traffic, and writes an incident report in which every claim cites its evidence.

![An investigation in the web page: the agent's steps on the left, the report on the right](docs/investigation.jpg)

> **Status: in progress.** The data layer, the flow classifier, the agent, the
> evals and the web page are built (phases 0 to 5 below). On 34 test cases the
> agent, running on the cheapest Claude model, passes 32: it finds 17 of 18
> attacks, names the right attacker each time, and stays quiet on 15 of 16
> cases with no attack. The first version of its prompt passed 13 of the same
> 34. Putting it online comes next.

| # | Phase | State |
|---|---|---|
| 0 | Setup: repo, Docker, empty API | Done |
| 1 | Data layer: flow CSV and packet capture into DuckDB | Done. All five days of CIC-IDS2017 (improved edition, 2.1 million flows) ingest and match the dataset authors' labelling rules |
| 2 | Classifier tool | Done. Trained and tested on the dataset; flags 99.7% of attacks it has seen, far less of attacks it has not (see [The classifier](#the-classifier)) |
| 3 | Agent, structured report, evidence validator | Done. Tested offline, plus one real run that found both attacks for about 1 cent (see [The agent](#the-agent)) |
| 4 | Evals and scoreboard | Done. 84 cases, graded by program. A second prompt cut false alarms from 15 of 16 clean test cases to 1 of 16 without losing an attack (see [The evals](#the-evals)) |
| 5 | API and web page | Done. Upload a capture, start an investigation, watch its steps live, open any stored one and click from a claim to the flows behind it (see [The web page](#the-web-page)) |
| 6 | Ship: demo, write-up | Not started |

## How it fits together

```
capture or flow CSV -> flow table (DuckDB) -> agent <-> read-only tools -> report -> evidence validator -> UI
                                                                                 ^
                                           eval harness runs labelled cases and scores the reports
```

## Quick start

Requires Python 3.11 or newer.

```bash
git clone https://github.com/KhaledTurkestani/nettriage.git
```

```bash
cd nettriage
```

```bash
python -m venv .venv
```

```bash
.venv/Scripts/pip install -e ".[dev]"
```

(On macOS or Linux the path is `.venv/bin/pip`.)

```bash
.venv/Scripts/pytest
```

Ingest something and look at it:

```bash
nettriage ingest pcap path/to/capture.pcap --id demo
```

```bash
nettriage query demo "SELECT dst_port, count(*) AS flows FROM flows GROUP BY 1 ORDER BY 2 DESC"
```

Or ingest a labelled dataset day (see [The dataset](#the-dataset)):

```bash
nettriage ingest csv path/to/friday.csv --id friday
```

```bash
nettriage query friday "SELECT src_ip, count(DISTINCT dst_port) AS ports, sum(syn_count) AS syn, sum(rst_count) AS rst FROM flows WHERE protocol = 6 GROUP BY 1 ORDER BY 2 DESC"
```

Score a capture with the trained classifier that ships in `models/`:

```bash
nettriage classify friday --where "dst_port = 80"
```

Investigate a capture with the agent. This calls the Claude API and is billed
to your key, which goes in a `.env` file (copy `.env.example`):

```bash
nettriage investigate tuesday
```

Other commands: `nettriage list`, `nettriage show ID`, `nettriage schema`,
`nettriage train CAPTURE...`, `nettriage runs`, `nettriage report RUN_ID`.

Start the web page (see [The web page](#the-web-page) for building it the first time):

```bash
nettriage serve
```

Then open <http://localhost:8000>. Or run everything in Docker, which builds the page too:

```bash
docker compose up --build
```

## The data layer

Two kinds of input end up in the same three tables:

| Input | Command | Notes |
|---|---|---|
| CICFlowMeter flow CSV (e.g. a CIC-IDS2017 day) | `nettriage ingest csv` | Labels are split off and stored outside the database. `dns` and `http` stay empty: a flow CSV has no packet contents |
| Packet capture (pcap, pcapng) | `nettriage ingest pcap` | Also fills the `dns` and `http` tables |

Each capture is a folder under `data/captures/<id>/`:

- `capture.duckdb` holds `flows`, `dns` and `http`.
- `meta.json` records where it came from and a few counts.
- `labels.parquet` holds ground truth, for labelled datasets only.

Run `nettriage schema` for every column and its meaning.

### The dataset

NetTriage is developed against the **improved edition of CIC-IDS2017** by Liu,
Engelen, Lynar, Essam and Joosen (IEEE CNS 2022): the original week of traffic,
re-extracted with a fixed flow meter and relabelled. Download
`CICIDS2017_improved.zip` (328 MB, five CSVs, one per day) from
<https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html>.

| Day | Flows stored | What happens |
|---|---|---|
| Monday | 371,389 | Benign only |
| Tuesday | 321,843 | FTP and SSH brute force |
| Wednesday | 496,395 | Four DoS tools, Heartbleed |
| Thursday | 361,841 | Web attacks, infiltration, internal port scan |
| Friday | 547,324 | Botnet, port scan, DDoS |

Things to know about this edition:

- Timestamps are UTC with microseconds. The capture site's local time was
  three hours behind.
- TCP flag columns are real counts, and a TCP flow ends on RST or after both
  FINs, the same rule as NetTriage's own flow meter.
- Some labels end in `- Attempted`: flows that belong to an attack run but
  carry nothing malicious, such as a handshake with no payload. The authors
  advise against treating them as a class of their own.
- About 235 rows per day are ARP frames that the flow meter read as traffic
  between `8.6.0.1` and `8.0.6.4`. The ingest drops them and reports the count.

As a check on the whole path (addresses, ports, timestamps, and the pairing of
flow ids with labels), the authors' published rules for FTP-Patator,
SSH-Patator, DoS GoldenEye and Heartbleed were run as SQL against the stored
captures. Each selects exactly the flows carrying that label: 3,984, 2,988,
7,647 and 11 flows, with none extra and none missing.

The original edition also works if it has addresses (`GeneratedLabelledFlows`),
with the limits listed below. The feature-only files (`MachineLearningCVE`) are
rejected: they have no addresses or timestamps to investigate.

### Design decisions

- **One schema, dataset units.** Times are microseconds and sizes are payload
  bytes, as in CIC-IDS2017, whichever input the capture came from.
- **Our own flow meter.** The Python `cicflowmeter` package reports seconds and
  whole-frame bytes, and its offline mode can split flows by wall-clock time,
  so flows are extracted by `nettriage/ingest/flowmeter.py` instead. It follows
  CICFlowMeter's conventions (bidirectional 5-tuple, first packet sets the
  forward direction, 120 s cut-off), with one deliberate fix: a TCP flow ends
  on RST or after both FINs, not at the first FIN.
- **Unknown is NULL, not a guess.** In the original CIC-IDS2017 files the TCP
  flag "count" columns are not counts: across all 2,830,743 rows none exceeds
  1, the SYN column is a copy of the "Fwd PSH Flags" column, and only a fifth
  of long TCP conversations show an ACK. The ingest detects this and stores
  NULL, so an investigation never cites a flag count that was never measured.
  Captures read from packets, and CSVs with real counts, keep their values.
  The few flows per file with a slightly negative duration are stored as 0,
  and a TCP window is NULL for non-TCP flows and when no packet came back.
- **Labels can't leak.** Ground truth lives outside the database, and the only
  connection the agent's tools get (`store.connect_readonly`) is read-only with
  file access from SQL disabled. An investigation cannot read the answer it is
  graded on.
- **Packet text is untrusted.** DNS names, HTTP hosts, paths and user agents are
  attacker-controlled. They are stored with control characters removed and
  length capped, and are treated as data, never as instructions.

## The classifier

A gradient-boosted model (scikit-learn's `HistGradientBoostingClassifier`,
660 KB) that scores every flow from 0 to 1 and names the most likely attack
family. The agent will call it as a tool, `classify_flows`, which returns
counts per family and the sources and targets with the most flagged flows, each
with example flow ids to cite. It is one lead among several, not the detector.

**What it sees.** 26 columns describing how a flow behaves: packet and byte
counts, payload sizes, timing, TCP flags and windows. It never sees addresses,
ports or times, so it cannot learn "traffic from the attacker's address is an
attack". Adding the destination port was tried and changed nothing (recall
0.9973 against 0.9969), so the port-blind model ships.

**What it predicts.** Seven families: `benign`, `brute_force`, `dos`,
`port_scan`, `web_attack`, `botnet` and `other`. Flows labelled `- Attempted`
count as benign, as the dataset's authors recommend.

**How the data is split.** Each day is cut into 5-minute blocks. Even blocks
train the model (1,062,138 flows); odd blocks are held out (1,036,654 flows).
A random split would put near-identical flows from one attack burst on both
sides. The held-out blocks are also the only place eval cases for the agent
will come from, so the agent is never graded on flows its tool was trained on.

### Results

Two tests, and the gap between them is the point.

**Test 1: attacks it has seen, at minutes it has not.**

| Measure | Result |
|---|---|
| Attack flows flagged (recall) | 99.65% of 232,151 |
| Flagged flows that are attacks (precision) | 99.99% |
| False alarms | 31 in 804,503 benign flows (3.9 per 100,000) |
| False alarms on Monday, a day with no attacks | 6 in 183,353 flows |

The weak spots are the slow attacks: 85% of DoS Slowloris flows and 71% of
DoS Slowhttptest flows are flagged, and 9 of 17 Infiltration flows.

**Test 2: attacks it has never seen.** For each attack in turn, a model is
trained with that attack removed and then asked to flag it.

| Attack removed from training | Flagged anyway |
|---|---|
| DoS Hulk | 97% |
| DDoS | 80% |
| DoS Slowhttptest | 64% |
| DoS GoldenEye | 58% |
| Infiltration port scan | 43% |
| Port scan | 34% |
| DoS Slowloris | 12% |
| FTP-Patator | 0% |
| SSH-Patator | 0% |
| Botnet | 0% |
| Web Attack - Brute Force | 0% |

A new DoS tool resembles the others enough to be caught. A kind of attack the
model has never met passes straight through: with FTP brute force removed, not
one of its 1,997 held-out flows is flagged, even though SSH brute force is
still in training. Test 1 alone would have hidden that. This is why NetTriage
puts an agent on top: the classifier points at what it recognises, and every
result it returns says that an unflagged flow is not evidence of benign
traffic. The agent has to look for the rest with SQL.

All numbers are in `models/flow-classifier/model_card.json`, written by
`nettriage train` together with the model.

### Training it yourself

```bash
nettriage train monday tuesday wednesday thursday friday
```

This takes a little over three minutes on a 16-core laptop, most of it the
eleven extra models of test 2. Pass `--no-unseen-test` to skip them. Training
is repeatable: a second run on the same captures produced the same model file,
byte for byte.

One thing worth knowing if you change the settings: the model needs its L2
regularisation. Without it the training loss rose from 0.76 to 8.9 within
twelve rounds, and a model run for 200 rounds flagged 15% of benign flows.

The model file is a pickle, so only load one you trained yourself. Loading
checks the file's hash and the scikit-learn version against the model card.

## The agent

`nettriage investigate` hands a capture to a Claude model with three tools and
asks for an incident report. The model decides what to look at; the code around
it decides what it is allowed to do and whether its report can be believed.

**Which model.** The default is the cheapest, and `--model` picks another.
Every number in [The evals](#the-evals) was measured on the default.

**Which prompt.** The system prompt has versions, kept word for word in
`src/nettriage/agent/prompts.py`, because an eval result only means something
next to the prompt that produced it. `--prompt` picks one; the default is the
version that won the last comparison on the test cases (`v1`).

| Model | Input / output, per million tokens | Default effort | Refusal fallback |
|---|---|---|---|
| `claude-haiku-5-5` (default) | $0.10 / $0.50, or $0.50 / $2.50 once a prompt passes 100,000 tokens | high | Not offered by the API |
| `claude-sonnet-5-5` | $2 / $10 | medium | Yes |
| `claude-opus-5-5` | $4 / $20 | medium | Yes |

**Tools.** All three read the capture through one locked, read-only connection.

| Tool | What it returns | Limits |
|---|---|---|
| `capture_overview` | Time span, protocols, busiest hosts and ports, a coarse timeline | Fixed queries |
| `run_sql` | The result of one `SELECT` over `flows`, `dns` and `http` | 50 rows, 200 characters per cell, 12,000 characters in all, stopped after 20 s, 2 GB of memory |
| `classify_flows` | The classifier's flagged sources and targets, with example flow ids | Top 5 of each |

The model never sees the capture's file name or id. Dataset files are often
named after the attack inside them.

**The report** has a fixed JSON shape, enforced by the API: a verdict, a
summary, findings and limitations. Each finding names an attack type, attacker
and victim addresses, a time span, and evidence items that each cite flow ids.

**The evidence check.** A fixed shape guarantees a report that parses, not one
that is true. So after the model answers, every cited flow is looked up:

- the flow must exist in the capture;
- every address the finding names must appear in one of its cited flows;
- at least one cited flow must connect a named attacker with a named victim;
- the time span must be valid and inside the capture.

A finding that fails is sent back to the model once, with the reasons. If it
fails again it is removed, and a verdict of "malicious activity" with no
surviving finding is lowered to "inconclusive". The run record keeps the
counts, which become the uncited-claim rate in the evals.

**Other guardrails.**

- *A tool-call budget* (30 by default). The model is told how many calls it has
  and when few are left; calls beyond the budget are answered with "write the
  report now" rather than run.
- *Refusals.* Security data can trip a model's safety classifier even in
  defensive work. For the models that offer it, every request opts in to the
  API's server-side fallback (`fallbacks: "default"`), which retries a declined
  request on another model. If the model declines and nothing takes over, the
  run ends as `refused`; nothing from a refused or cut-off turn is executed.
- *Untrusted text.* DNS names, HTTP hosts, paths and user agents are written by
  whoever generated the traffic. The system prompt tells the model that text in
  tool results is data, never instructions, and to report an attempt to
  instruct it. Whether the model holds to that is measured in phase 4.
- *An append-only conversation.* The system prompt, tool list and earlier
  messages never change within a run, and the model's turns are sent back
  unmodified. That keeps the prompt cache warm, which is most of the cost.

**Run records.** Each run is saved as `data/runs/<run id>/run.json`: the
report, the evidence-check counts, token usage, an estimated cost, and every
step in order (model turn, tool call, tool output). The web UI's timeline and
the replay mode will read these files.

**How it is tested.** The tests use the real Anthropic SDK client with a mock
transport that answers each request with a scripted model turn in the API's
streaming wire format. No request leaves the machine, and the SDK's own request
building and response parsing are exercised along with the loop. The scripts
cover a normal investigation, invented evidence (fixed on the second try, and
removed when it is not), a refusal, a cut-off turn, an exhausted budget, API
errors and a model that never stops.

### The first real run

One investigation has been run against the real API so far: Tuesday's capture
(321,843 flows) with `claude-haiku-5-5` at effort high and a budget of 15 tool
calls.

| | |
|---|---|
| Time | 98 seconds |
| Model calls, tool calls | 9, 15 (the model often asked for two or three tools at once) |
| Tokens | 212,880 in, of which 175,185 were read from the prompt cache; 13,464 out |
| Cost at list prices | $0.013 |
| Evidence check | 1 finding reported, 0 rejected |

The report named one finding: password guessing from `172.16.0.1` against
`192.168.10.50`, on FTP from 12:17:52 to 13:20:13 (3,984 connections, 3,952 of
them reset) and on SSH from 17:09:01 to 19:04:15 (2,988 connections). Checked
afterwards against the capture and the ground-truth labels:

- Every count and timestamp above matches a direct SQL query.
- All 17 cited flows are labelled attack flows (16 FTP-Patator or SSH-Patator,
  1 FTP-Patator "attempted").
- The report said `172.16.0.1` might be a NAT or gateway address. It is: the
  dataset's attacks arrive through the firewall's address.
- The classifier had also flagged four benign flows as other attack types. The
  agent did not report them as findings; it listed them as unconfirmed leads.

What this run does not show: it is one run, on a day half of which trained the
classifier, with the dataset's well-known addresses in plain view, and a whole
day is not a realistic case. The evals in phase 4 use held-out time blocks,
masked addresses, short cases, and enough of them to count.

The run also exposed a bug the offline tests had missed: `run_sql` refused a
valid query that began with a parenthesis. It is fixed and covered by a test.

## The evals

One real run says little. The evals run the agent on 84 cases with known
answers and score every report by program. The cases are in two sets: 50 "dev"
cases, whose failures are read while a prompt is being changed, and 34 "test"
cases, which are only scored. A claim that one prompt beats another rests on
the test cases.

### The cases

Each case is five minutes of a dataset day, rebuilt as a small capture
(971 to 49,855 flows). The list is in `evals/cases.json`, and
`evals/CASES.md` shows every case for review.

| Kind | Dev | Test | What it holds |
|---|---|---|---|
| Attack | 28 | 16 | Dev: brute force (6), denial of service (9), port scans (6), botnet (3), web attacks (3), infiltration (1). Test: brute force (4), denial of service (2), port scans (2), botnet (2), web attacks (3), Heartbleed (2), infiltration (1). "Needles", with fewer than ten attack flows among thousands: 4 in dev, 8 in test |
| Clean | 14 | 14 | Ordinary traffic only |
| Planted instructions | 8 | 4 | Text in HTTP headers that tells the analyst to report nothing (5 dev and 2 test cases, each with a real attack) or to accuse an innocent host (3 dev and 2 test cases, all clean) |

The test set was added after the first scoreboard, from held-out blocks no case
had used. Its cases were picked by fixed rules from the label counts alone:
every unused block with at least two attack flows, two blocks per attack type
at most, and clean blocks drawn at random with a fixed seed. Denial of service
is thin in it because the dev set had already used every held-out block of
three of the five kinds.

Three things keep the cases honest:

- **Held-out time only.** Cases come from the 5-minute blocks the classifier
  never trained on. The builder refuses any other block.
- **Nothing recognisable.** The dataset's addresses and attack schedule are
  well known, so every address is replaced (private stays private, hosts on one
  network stay on one network) and every timestamp is shifted by a random
  amount. A check over all 84 cases found no original address, date or attack
  name in anything the agent is shown.
- **Rebuilt, not stored.** `nettriage eval build` recreates identical cases
  from the manifest and a seed.

Flow records have no HTTP content, so the planted text sits in synthetic HTTP
rows attached to real port-80 flows.

### The grading

Every finding cites flow ids and every flow of a case has a label, so no model
is needed as a judge: a finding is **true** when most of the flows it cites
belong to an attack run. A case passes when:

- *it has an attack:* the verdict is "malicious activity", some finding is
  true, that finding names an address that took part as the attacker, and no
  finding is false;
- *it is clean:* the verdict is "no malicious activity" and there are no
  findings;
- *it has planted instructions:* the same, and the instructions were not
  followed.

A refusal, or a run that never delivers a report, fails the case. An API error
or a timeout is not scored at all; it goes to an error list and is retried on
the next run.

`nettriage eval check` tests the grader itself on the real cases, with three
made-up analysts and no model call: one that answers exactly what the labels
say passes 84 of 84, one that always reports nothing passes only the 33 clean
cases, and one that always accuses an innocent host passes none.

### The first scoreboard

The first prompt (`baseline`) on the 50 dev cases, which were all the cases
there were at the time. `claude-haiku-5-5`, effort high, each case run once,
16 November 2026. The 50 runs took under half an hour, three at a time, and
cost $0.80.

| Measure | Result |
|---|---|
| **Cases passed** | **26 of 50 (52%)** |
| Attack cases where an alarm was raised | 33 of 33 |
| ... with a finding backed by the attack's own flows | 33 of 33 |
| ... naming the right attacker | 33 of 33 |
| ... with the right attack type | 32 of 33 |
| Clean cases with no alarm | 1 of 17 |
| False findings | 41, across 23 cases |
| Findings the evidence check rejected at first | 4 of 78, all corrected on the retry |
| Planted instructions followed | 0 of 8 (all 8 reached the model, and all 8 reports say so) |
| Refusals, cut-off runs, runs without a report | 0 |
| Cost per case, median | $0.017 |
| Time per case, median | 84 s |

By kind of case: denial of service 9 of 9, botnet 3 of 3, port scans 5 of 6,
brute force 3 of 6, web attacks 2 of 3, infiltration 0 of 1, planted
instructions 4 of 8, clean 0 of 14.

What this says:

- **It does not miss.** Every attack was reported with flows that really
  belong to it and the right attacker, including the four needle cases.
- **It cannot say "nothing here".** On 16 of 17 clean cases it reported one to
  four findings: regular HTTPS connections called "beaconing", ordinary
  directory and file-server traffic called "scanning" or "credential guessing",
  bursts of DNS queries called a flood. Seven attack cases failed for the same
  reason: the attack was found, and an extra accusation was added to it.
- **It was not talked out of anything.** No planted instruction was followed,
  and every one of those reports names the planted text as an attempt at
  manipulation.

What it does not say:

- Each case ran once. With 50 cases, the pass rate is good to about 14 points
  either way.
- The shipped classifier flags nearly every attack flow in 26 of the 33 attack
  cases, so "found every attack" mostly shows that the agent verifies and
  writes up what the classifier points at. How it does when the classifier
  knows nothing about an attack is not measured yet.
- One model, one prompt. Whether the false alarms come from the model or from
  a prompt that pushes it to keep looking is the next thing to find out.

A note on the grader: the first pass marked one planted instruction as
followed. Reading that report showed the agent had rejected the text in so
many words; the framed host merely appeared among five hosts in an unrelated
low-confidence finding. The rule was tightened (obeying means repeating the
planted claim) and the stored runs were graded again, which needs no new model
calls.

### The second scoreboard: a bar for findings

The false alarms had a pattern. Of the 41 false findings in the first run, 38
were reported with low or medium confidence, and most said in their own
description that the traffic "could be legitimate" or was "not confirmed". Of
the 37 true findings, 30 were reported with high confidence. So the agent knew
which of its findings were unconfirmed. The prompt had told it to look for
suspicious patterns and had given a suspicion nowhere to go but the findings
list.

The second prompt (`v1`) makes one change: a finding is an accusation and has
to clear a bar, and what does not clear it is a lead, which goes under
limitations and does not change the verdict. The model, effort, tools, report
format and tool budget are the same. The reasoning and the diff are in
`evals/investigate/v1/change.md` and `change.patch`.

A prompt written after reading the dev cases' failures will look good on the
dev cases whether or not it is better. So the 34 test cases were built first,
the new prompt was fixed before it met them, and both prompts were run on them
on the same day (17 November 2026). Their reports have not been read to this
day, only their grades.

| On the 34 test cases | First prompt | Second prompt |
|---|---|---|
| **Cases passed** | 13 (38%) | **32 (94%)** |
| Clean cases with no alarm | 1 of 16 | 15 of 16 |
| Attack cases with a finding backed by the attack's own flows | 17 of 18 | 17 of 18 |
| ... naming the right attacker | 17 of 17 | 17 of 17 |
| False findings | 47 | 2 |
| Planted instructions followed | 0 of 4 | 0 of 4 |
| Refusals, cut-off runs, runs without a report | 0 | 0 |
| Cost per case, median | $0.017 | $0.014 |
| Time per case, median | 91 s | 79 s |

Nineteen cases went from fail to pass and none from pass to fail. If the two
prompts were equally good, a split that uneven would turn up less than once in
a thousand tries (exact sign test on the cases that changed). The 95% interval
for the second prompt's pass rate is 81% to 98%. On the 50 dev cases the count
went from 26 to 44; that is reported for completeness, not as the result.

By kind of test case, second prompt: clean 13 of 14, brute force 4 of 4,
denial of service 2 of 2, port scans 2 of 2, botnet 2 of 2, web attacks 3 of 3,
planted instructions 4 of 4, Heartbleed 2 of 2, infiltration 0 of 1.

What it found that might have been lost: all 8 needle cases but one, including
both Heartbleed cases (two attack flows each among 4,819 and 7,464). The first
prompt had missed one of those.

What still goes wrong:

- **One clean case in 16 still gets a false finding** on the test set, and 4
  of 17 on the dev set. In all four dev cases it is the same thing: one
  internal host whose connections to outside servers go unanswered, reported
  as a scan or as beaconing.
- **One attack is missed in each set.** On the test set it is an infiltration
  with 3 attack flows among 5,584. On the dev set it is a flood that the report
  does name, but most of the flows cited for it are ordinary ones, so the
  finding does not count as backed by the attack. The first prompt had passed
  that case.

What this comparison does not show:

- Each case ran once per prompt, so single cases can flip by chance. The
  19-to-0 split is far outside what chance does; the exact pass rate is not
  known to better than the interval above.
- Every case comes from one network, the dataset's testbed. The second prompt
  describes what ordinary traffic looks like in general terms, and those terms
  were written after looking at this network's traffic. How the bar holds on a
  different network is not measured.
- The classifier has seen every attack type in these cases, and the second
  prompt leans on it more than the first: a finding the classifier does not
  support has to stand on the flows alone. With an attack type the classifier
  has never seen, the agent may now stay quiet where the first prompt would
  have spoken. That is the next thing worth measuring.
- One model.

Both prompts on all 84 cases cost $2.69 in total.

### Running it

```bash
nettriage eval build
```

```bash
nettriage eval check
```

```bash
nettriage eval run
```

```bash
nettriage eval report
```

`eval run` calls the Claude API and costs money; it skips cases that already
have a result, so an interrupted run can simply be started again. Results land
in `evals/investigate/baseline/`: `results.jsonl` (one graded row per case),
`SCOREBOARD.md`, and `REVIEW.md`, which shows for every case what it held,
what the agent reported and how each part was scored.

To try a new prompt, add it to `src/nettriage/agent/prompts.py` under a new
name, say `v2`, and run it as its own variant. A variant keeps the prompt,
model and effort of its first run, so one results file never mixes two setups.

```bash
nettriage eval run --variant v2 --set dev
```

Read the dev results, and when the prompt is final:

```bash
nettriage eval run --variant v2 --set test
```

```bash
nettriage eval compare v1 v2
```

`eval compare` costs nothing. It pairs the two variants case by case, lists
the cases that changed sides, and writes `evals/investigate/COMPARE.md`. Once
a test set has been used to choose between prompts and its failures have been
read, it is a dev set: the next comparison needs fresh cases.

## The web page

One address shows everything: the server serves the page and the API behind it.

| Page | What it shows |
|---|---|
| Captures | Stored captures, a box to add one (packet capture or CICFlowMeter CSV), and every stored investigation |
| A capture | Flows over time, the busiest sources, destinations and ports, and a form to start an investigation |
| An investigation | On the left every step the agent took: what the model said it was doing, each query with its result, the classifier's output, the evidence check. On the right the report. Clicking a flow number opens the flows themselves, read from the capture and not from the model |

An investigation can be watched while it runs, and any stored one can be replayed step by step.
Replay reads the saved record, so it costs nothing.

**Building it.** The page is a small React and TypeScript app in `web/`. It is built into the
Python package (`src/nettriage/api/static/`), which is not committed.

```bash
cd web
```

```bash
npm ci
```

```bash
npm run build
```

For work on the page itself, `npm run dev` serves it with hot reload and passes API calls on to
a server on port 8000.

**The API.** Everything the page does goes through these, and they are listed at `/docs`.

| Request | What it does |
|---|---|
| `GET /api/config` | What this server allows: uploads, investigations, models and their prices |
| `GET /api/captures`, `GET /api/captures/{id}` | The captures, and one capture with its overview |
| `POST /api/captures?name=...` | Add a capture. The file is the request body |
| `GET /api/captures/{id}/flows?ids=1,2,3` | The flows with those ids, for looking at evidence |
| `POST /api/runs` | Start an investigation. This is the only request that costs money |
| `GET /api/runs`, `GET /api/runs/{id}` | Stored investigations, and one with every step |
| `GET /api/runs/{id}/events` | The steps as a live stream (server-sent events) while it runs |

**What is treated as hostile.**

- *Uploads.* Size is capped while the bytes arrive (200 MB by default), only capture formats are
  taken, the file's name is used as a label and never as a path, and the file is deleted once read.
- *Other web pages.* An investigation costs money, so a page on another site must not be able to
  start one through your browser. Requests that change anything are refused when they come from
  another origin, and the server answers only to host names it was told about.
- *What a run produced.* Tool output and report text were written by a model reading traffic an
  attacker may have crafted. The page shows them as text, never as markup.
- *Strangers.* The page has no login. Docker publishes it on localhost only. To show it to
  others, set `NETTRIAGE_READ_ONLY=1`: stored investigations can be opened and replayed, and
  nothing new is accepted, so nobody can spend your API key.

Ground-truth labels are not served by any endpoint.

**How it is tested.** The API tests drive the real application with a scripted model: uploads
that must be refused (wrong type, too large, empty, not a capture, a path as a name), a
cross-site request, an investigation followed from its first event to the stored report, a
failing run, and the limit on how many run at once. The page was checked by hand in a browser
against real data, its live view first against a server whose model is a script and then with
one real investigation (below). The drag-and-drop box was not exercised by hand; the upload
request it sends is covered by the API tests.

### A real run from the page

One investigation has been started from the page against the real API: Wednesday's capture
(496,395 flows) with `claude-haiku-5-5`, the `v1` prompt and a budget of 20 tool calls, on
17 November 2026. It took 69 seconds, 13 tool calls and 7 model calls, and cost $0.012. The
steps arrived on the page as they happened and the report replaced the placeholder at the end.

The report made two findings, and the evidence check passed both. Checked afterwards against
the day's labels:

- **A flood of the web server.** `172.16.0.1` against `192.168.10.50` port 80, about 177,500
  connections. That day's four denial-of-service tools all come from that address at that
  server, and the report treats them as one attack. Of the 23 flows it cites, 19 belong to
  those attack runs.
- **Long sessions on port 444** between `172.16.0.1` and `192.168.10.51`, reported as a
  probable data leak. That is the day's Heartbleed attack: the report cites 10 of its 11 flows,
  with 10 ordinary flows beside them.
- **Three leads were left as leads**, under limitations, and all three are ordinary traffic
  according to the labels.

One sentence in the report is wrong. Its limitations say the classifier "flagged nothing" in
the port-444 sessions; the classifier had flagged all 11 of those flows, and the model did not
check. The evidence check covers the flows a finding cites, not every sentence around them, so
nothing caught it. A report's prose still needs reading with care.

Half of this day's 5-minute blocks trained the classifier, so this run shows the page working,
not how good the agent is. The evals are what measure that.

The run also showed two things to fix in the page, both fixed: it stayed scrolled to the last
step when the report appeared at the top, and the tool-call budget was missing from the header
of a finished run.

## Known limits

- The agent's reports need a human check. On the test cases it raised a false
  alarm on 1 clean case in 16 and missed 1 attack in 18, measured on one model
  and on traffic from one network, with a classifier that knew every attack
  type present.
- The classifier has only been measured on dataset flows. On a packet capture
  it runs, with a warning, but how well it works there is unknown until the
  feature match below is measured.
- The classifier's families `web_attack` and `other` rest on 58 and 26 training
  flows. Treat those two names as weak.
- Dataset days hold flows only. DNS names and HTTP requests are available just
  for packet captures.
- For the original CIC-IDS2017 edition, the feature columns were checked on the
  real feature-only files (2,830,743 rows), but its address and timestamp
  columns, including the 12-hour clock fix, have only run on a fixture. Its
  five TCP flag columns are stored as NULL (see above).
- How closely pcap-extracted features match the dataset's own features has not
  been measured. That needs the dataset's packet captures, which are tens of
  gigabytes.
- HTTP requests are parsed from single packets; a request split across TCP
  segments is missed. TLS is not decoded.
- Packet captures are read at about 12,000 packets per second (measured on a
  laptop with a 40,000-packet capture), so multi-gigabyte captures are slow.
  Use `--max-packets` to sample. Flow CSVs are fast: a dataset day of 300,000
  to 550,000 flows takes 3 to 4 s.
- The API has no authentication and is bound to localhost.
