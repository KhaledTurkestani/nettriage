"""Ingest paths: each one turns an input file into the canonical tables."""


class IngestError(Exception):
    """The input file could not be turned into a capture."""
