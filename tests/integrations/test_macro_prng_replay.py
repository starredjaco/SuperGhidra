"""
test_macro_prng_replay.py - Unit tests for high-volume macro-replay and anchor scanner.
"""

import struct

from superghidra.integrations.macro_prng_replay import (
    find_prng_heap_anchors,
    native_tick_replay,
    precompute_prng_table,
    solve_draw_budget,
)


def test_precompute_and_anchor_search():
    # Precompute 1000 draws
    seed_0 = 987654321
    table = precompute_prng_table(seed_0, count=1000)

    assert len(table.seeds) == 1000
    assert table.seeds[0] == seed_0

    # Pick seed at draw #42
    seed_42 = int(table.seeds[42])

    # Construct synthetic heap page containing seed_42 at offset 0x40
    heap_page = bytearray(256)
    struct.pack_into("<Q", heap_page, 0x40, seed_42)

    anchors = find_prng_heap_anchors(bytes(heap_page), table, heap_base_addr=0x76380000)
    assert len(anchors) == 1
    assert anchors[0].draw_index == 42
    assert anchors[0].heap_runtime_addr == 0x76380040


def test_solve_draw_budget():
    # 820 ticks, 100,000 total draws
    # 120 ambient entities drawing 1 draw/tick = 120 * 820 = 98,400 draws
    fixed = [("LogicAmbientAnimal", 1, 120)]
    sol = solve_draw_budget(delta_ticks=820, total_delta_draws=100000, fixed_callers=fixed)

    assert sol.is_feasible is True
    assert sol.baseline_fixed_draws == 98400
    assert sol.residual_event_draws == 1600


def test_native_tick_replay():
    entities = [{"name": "fox", "draws_per_tick": 2, "vtable_rva": 0x1471D08}]
    final_seed, events = native_tick_replay(initial_seed=12345, num_ticks=10, entities=entities)

    assert len(events) == 20
    assert events[0]["tick"] == 0
    assert events[-1]["tick"] == 9
