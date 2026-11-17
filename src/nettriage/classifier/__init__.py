"""A flow classifier the agent can call as a tool.

It is a gradient-boosted model trained on labelled dataset days. It scores each
flow from its behaviour (sizes, timing, TCP flags) and never sees addresses,
ports or times, so it cannot memorise the dataset's hosts.
"""


class ClassifierError(Exception):
    """The classifier could not be trained, loaded or run."""
