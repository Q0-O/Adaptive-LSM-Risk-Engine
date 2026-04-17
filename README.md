Experimental Linux Security Module (LSM) implemented using eBPF.
Implements an adaptive risk-scoring mechanism for access control based on runtime signals, including rate limiting, policy evaluation, and lightweight behavioral tracking with decay logic.

Kernel-level decision logic is implemented using eBPF LSM hooks with heuristic scoring. No formal security model is defined, and no production guarantees are provided.

Limitations:
	Heuristic scoring with arbitrary weights and thresholds
	No formal threat model or security validation
	Simplified behavioral tracking without strong consistency guarantees
	Not designed or hardened for adversarial environments

Research-oriented implementation for eBPF LSM decision systems.
