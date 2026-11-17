"""Investigations started from the web page.

An investigation takes a minute or two, so it runs on its own thread and the
page follows it through a stream of events: the same events the run record
stores. A page that connects late, or reconnects, is sent the earlier events
first, so every viewer sees the whole run.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator

from ..agent import AgentError
from ..agent.loop import investigate, new_run_id
from ..agent.runs import save_run

# Each running investigation spends money, so only a few may run at once.
MAX_RUNNING = 2
KEEP_FINISHED = 20


class LiveRun:
    """One investigation in progress, or just finished, and the events it has produced so far."""

    def __init__(self, run_id: str, capture_id: str, settings: dict):
        self.run_id, self.capture_id, self.settings = run_id, capture_id, settings
        self.events: list[dict] = []
        self.finished = False
        self._changed = threading.Condition()

    def add(self, event: dict) -> None:
        with self._changed:
            self.events.append(event)
            self._changed.notify_all()

    def finish(self) -> None:
        with self._changed:
            self.finished = True
            self._changed.notify_all()

    def stream(self, after: int = 0, heartbeat: float = 15.0) -> Iterator[dict | None]:
        """Events from number ``after`` on, as they arrive. ``None`` means "still running, nothing new".

        Ends once the run has finished and everything has been sent.
        """
        position = max(0, after)
        while True:
            with self._changed:
                if position >= len(self.events) and not self.finished:
                    self._changed.wait(timeout=heartbeat)
                batch = self.events[position:]
                finished = self.finished
            if batch:
                position += len(batch)
                yield from batch
            elif finished:
                return
            else:
                yield None


class LiveRuns:
    def __init__(self, max_running: int = MAX_RUNNING):
        self.max_running = max_running
        self._runs: OrderedDict[str, LiveRun] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, run_id: str) -> LiveRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def running(self) -> list[LiveRun]:
        with self._lock:
            return [run for run in self._runs.values() if not run.finished]

    def start(self, capture_id: str, *, client, model: str, effort: str, max_tool_calls: int, prompt: str,
              run: Callable = investigate) -> LiveRun:
        """Start an investigation on its own thread. Every call spends money on the caller's API key."""
        live = LiveRun(new_run_id(capture_id), capture_id, {
            "model": model, "effort": effort, "max_tool_calls": max_tool_calls, "prompt": prompt,
        })
        with self._lock:
            if sum(1 for other in self._runs.values() if not other.finished) >= self.max_running:
                raise AgentError(f"{self.max_running} investigations are already running. Wait for one to finish.")
            self._runs[live.run_id] = live
            finished = [run_id for run_id, other in self._runs.items() if other.finished]
            for run_id in finished[:-KEEP_FINISHED]:
                del self._runs[run_id]

        def work() -> None:
            try:
                result = run(capture_id, client=client, model=model, effort=effort, max_tool_calls=max_tool_calls,
                             prompt=prompt, on_event=live.add, run_id=live.run_id)
                save_run(result)
            except AgentError as exc:
                live.add({"n": len(live.events) + 1, "type": "end", "status": "failed", "error": str(exc)})
            except Exception as exc:  # whatever happens, the page must be told the run is over
                live.add({"n": len(live.events) + 1, "type": "end", "status": "failed",
                          "error": f"The server hit an unexpected error ({type(exc).__name__})."})
            finally:
                live.finish()

        threading.Thread(target=work, name=f"investigation-{live.run_id}", daemon=True).start()
        return live
