"""Analytic and hand-computed game fixtures for the solver verifier (P3-1).

These are the closed-form reference games the EV / best-response / exploitability
machinery is validated against (ADR-0017 sec.5, REV-20260705-phase2-gate2-fable5 sec.6
layer L1): the AKQ half-street game (unique equilibrium, full closed form), Kuhn
poker (a non-unique equilibrium family, checked by game value + exploitability
only), and tiny hand-computed toy trees for unit-level EV / reach / best response.
"""
