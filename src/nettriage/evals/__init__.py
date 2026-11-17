"""Evals: labelled cases, graders and a runner that score the agent's reports.

Everything here is on the grading side of the wall. It reads ground-truth
labels, which the agent never can.
"""


class EvalError(Exception):
    """An eval case could not be built, run or graded."""
