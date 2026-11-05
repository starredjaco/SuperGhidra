"""
test_concolic_trace_slicer.py - Unit tests for short-window concolic PRNG draw correlator.
"""


from superghidra.integrations.concolic_trace_slicer import (
    ConcolicPRNGCorrelator,
    default_lcg_step,
)


def test_prng_step_and_reconciliation():
    correlator = ConcolicPRNGCorrelator(default_lcg_step)
    seed_0 = 12345
    # Step forward 5 times to compute target seed
    s = seed_0
    for _ in range(5):
        s, _ = default_lcg_step(s)
    target_seed = s

    candidates = [
        {"caller_rva": 0x00D69EE4, "object_ptr": 0x7638C4A21200, "bound": 20},
        {"caller_rva": 0x00D6B494, "object_ptr": 0x7638C4A21200, "bound": 10},
        {"caller_rva": 0x00D6B668, "object_ptr": 0x7638C4A21200, "bound": 0, "is_dead_draw": True},
    ]

    trace = correlator.reconcile_window(
        initial_seed=seed_0,
        target_final_seed=target_seed,
        max_draws=100,
        candidates=candidates,
    )

    assert trace.total_draws == 5
    assert trace.final_seed == target_seed
    assert trace.drift_detected is False
    assert len(trace.matched_draws) == 5
    assert trace.dead_draw_count >= 1
