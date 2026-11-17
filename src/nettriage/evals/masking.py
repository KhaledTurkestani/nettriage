"""Replace the addresses in a case with made-up ones.

The dataset's addresses are famous: any model that has read about CIC-IDS2017
knows that 172.16.0.1 is the attacker and 192.168.10.50 the victim. A case
that showed them would test memory, not investigation. Each case therefore
gets its own random mapping, which keeps what an analyst relies on:

* private addresses stay private, and hosts that shared a /24 still share one,
  so the internal network is still recognisable as a network;
* public addresses stay public;
* multicast, broadcast and unspecified addresses are left alone, because their
  meaning is in the address itself.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

import numpy as np


def _keep(address: ipaddress.IPv4Address) -> bool:
    return (
        address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local
        or address == ipaddress.IPv4Address("255.255.255.255")
    )


def build_ip_map(addresses: Iterable[str], rng: np.random.Generator) -> dict[str, str]:
    """A one-to-one mapping from each address to its replacement. Deterministic for a given rng."""
    mapping: dict[str, str] = {}
    prefixes: dict[tuple[int, int, int], tuple[int, int]] = {}
    hosts: dict[tuple[int, int, int], list[int]] = {}
    used_prefixes: set[tuple[int, int]] = set()
    used_public: set[int] = set()

    for text in sorted(set(addresses)):
        try:
            address = ipaddress.IPv4Address(text)
        except (ipaddress.AddressValueError, ValueError):
            mapping[text] = text  # not IPv4: nothing known about it, leave it
            continue
        if _keep(address):
            mapping[text] = text
            continue
        a, b, c, d = address.packed
        if address.is_private:
            key = (a, b, c)
            if key not in prefixes:
                while True:
                    candidate = (int(rng.integers(1, 255)), int(rng.integers(0, 255)))
                    if candidate not in used_prefixes:
                        break
                used_prefixes.add(candidate)
                prefixes[key] = candidate
                hosts[key] = [0, *(int(h) for h in rng.permutation(np.arange(1, 255))), 255]
            x, y = prefixes[key]
            mapping[text] = f"10.{x}.{y}.{hosts[key][d]}"
            continue
        while True:
            number = int(rng.integers(1 << 24, 223 << 24))
            candidate_address = ipaddress.IPv4Address(number)
            if candidate_address.is_global and number not in used_public and number & 0xFF not in (0, 255):
                break
        used_public.add(number)
        mapping[text] = str(candidate_address)
    return mapping
