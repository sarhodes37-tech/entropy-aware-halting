import math
from dataclasses import dataclass
from typing import Any

@dataclass
class StepMetrics:
    step_index: int
    entropy: float
    delta_h: float
    eta: float
    utility: float
    utility_gain: float
    state: Any

@dataclass
class DecisionResult:
    halt: bool
    directive: str
    best_state: Any
    best_step: int
    best_utility: float
    utility_loss_avoided: float
    termination_step: int
    current_utility: float
    peak_utility: float

class EntropyAwareScheduler:
    def __init__(
        self,
        value_of_information=100,
        divergence_threshold=0.15,
        negative_yield_window=2,
        entropy_delta_threshold=0.005,
        stagnation_window=3,
        confidence_threshold=0.01,
        utility_epsilon=0.5,
        minimum_steps_before_convergence=3
    ):
        specs = [
            ("value_of_information", value_of_information, "number", True),
            ("divergence_threshold", divergence_threshold, "number", False),
            ("negative_yield_window", negative_yield_window, "integer", True),
            ("entropy_delta_threshold", entropy_delta_threshold, "number", False),
            ("stagnation_window", stagnation_window, "integer", True),
            ("confidence_threshold", confidence_threshold, "number", False),
            ("utility_epsilon", utility_epsilon, "number", False),
            ("minimum_steps_before_convergence", minimum_steps_before_convergence, "integer", False),
        ]

        for name, value, type_name, is_positive in specs:
            if type_name == "number" and not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number")
            if type_name == "integer" and not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")

            if is_positive and value <= 0:
                raise ValueError(f"{name} must be positive")
            if not is_positive and value < 0:
                raise ValueError(f"{name} must be non-negative")

        self.V = value_of_information
        self.divergence_threshold = divergence_threshold
        self.negative_yield_window = negative_yield_window
        self.entropy_delta_threshold = entropy_delta_threshold
        self.stagnation_window = stagnation_window
        self.confidence_threshold = confidence_threshold
        self.utility_epsilon = utility_epsilon
        self.minimum_steps_before_convergence = minimum_steps_before_convergence

        self.entropy_history = []
        self.utility_history = []
        self.history = []
        self.total_cost = 0
        self.best_state = None
        self.best_step = -1
        self.best_utility = float("-inf")
        self.initial_entropy = None

    def reset(self) -> None:
        """Resets trajectory state tracking metrics for a new execution trajectory/session."""
        self.entropy_history = []
        self.utility_history = []
        self.history = []
        self.total_cost = 0
        self.best_state = None
        self.best_step = -1
        self.best_utility = float("-inf")
        self.initial_entropy = None

    def entropy(self, probabilities):
        """
        Input Contract for Probability Distributions:
        - Must be a 1D sequence or 1D Tensor of numeric probability values.
        - Every element must be finite (no NaN, +inf, -inf) and non-negative (>= 0.0).
        - Sum of probabilities must be strictly positive and finite (> 0.0).
        - Epsilon addition is NOT used as a substitute for validation.
        """
        if hasattr(probabilities, "ndim") and probabilities.ndim != 1:
            raise ValueError("Probabilities must be a 1D distribution sequence")

        # Pure Python / List / Tuple / Non-Tensor validation
        if isinstance(probabilities, (list, tuple)):
            if len(probabilities) == 0:
                raise ValueError("Probabilities sequence cannot be empty")

            total_sum = 0.0
            p_clean = []
            for v in probabilities:
                if isinstance(v, (list, tuple, dict, set)):
                    raise ValueError("Probabilities must be a 1D distribution sequence")
                try:
                    fval = float(v)
                    if math.isnan(fval) or math.isinf(fval):
                        raise ValueError("Probabilities cannot contain NaN or non-finite values")
                    if fval < 0.0:
                        raise ValueError("Probabilities cannot contain negative values")
                    total_sum += fval
                    p_clean.append(fval)
                except (TypeError, ValueError) as e:
                    if "NaN or non-finite" in str(e) or "negative values" in str(e) or "1D distribution" in str(e):
                        raise e
                    raise ValueError(f"Invalid probability value: {v}") from e

            if total_sum <= 0.0 or math.isnan(total_sum) or math.isinf(total_sum):
                raise ValueError("Probabilities must sum to a positive finite value")

        # Lazy import isolates heavy tensor packages to execution boundary
        try:
            import torch
        except ImportError:
            # Pure Python Shannon Entropy H(P) = - sum(p * log2(p)) where 0 * log2(0) = 0
            h = 0.0
            for p in p_clean:
                if p > 0.0:
                    h -= p * math.log2(p)
            return h

        if not isinstance(probabilities, torch.Tensor):
            probabilities = torch.tensor(probabilities, dtype=torch.float64)

        if probabilities.ndim != 1:
            raise ValueError("Probabilities must be a 1D distribution sequence")

        if torch.any(torch.isnan(probabilities)) or torch.any(torch.isinf(probabilities)):
            raise ValueError("Probabilities cannot contain NaN or non-finite values")

        if torch.any(probabilities < 0.0):
            raise ValueError("Probabilities cannot contain negative values")

        prob_sum = torch.sum(probabilities).item()
        if prob_sum <= 0.0 or math.isnan(prob_sum) or math.isinf(prob_sum):
            raise ValueError("Probabilities must sum to a positive finite value")

        # Tensor calculation without epsilon addition
        pos_p = probabilities[probabilities > 0.0]
        if pos_p.numel() == 0:
            return 0.0

        return -torch.sum(pos_p * torch.log2(pos_p)).item()

    def step(self, probabilities, cost, state):
        step_index = len(self.history)
        H = self.entropy(probabilities)

        if self.initial_entropy is None:
            self.initial_entropy = H

        self.entropy_history.append(H)
        self.total_cost += cost

        delta_h = 0
        if step_index > 0:
            delta_h = self.entropy_history[-2] - self.entropy_history[-1]

        eta = 0
        if step_index > 0:
            if self.initial_entropy > 0 and cost > 0:
                eta = (delta_h / self.initial_entropy) * self.V / cost

        utility, utility_gain = self._update_utility(H, state, step_index)

        metric = StepMetrics(step_index, H, delta_h, eta, utility, utility_gain, state)
        self.history.append(metric)

        directive, loss_avoided = self._evaluate_convergence(step_index, H, utility, utility_gain)

        return DecisionResult(
            halt=directive != "CONTINUE",
            directive=directive,
            best_state=self.best_state,
            best_step=self.best_step,
            best_utility=self.best_utility,
            utility_loss_avoided=loss_avoided,
            termination_step=step_index,
            current_utility=utility,
            peak_utility=self.best_utility
        )

    def _update_utility(self, H, state, step_index):
        utility = self.V * (self.initial_entropy - H) - self.total_cost

        utility_gain = 0
        if self.utility_history:
            utility_gain = utility - self.utility_history[-1]

        self.utility_history.append(utility)

        if utility > self.best_utility:
            self.best_utility = utility
            self.best_state = state
            self.best_step = step_index

        return utility, utility_gain

    def _evaluate_convergence(self, step_index, H, utility, utility_gain):
        directive = "CONTINUE"
        negative_yield_detected = False
        if len(self.history) >= self.negative_yield_window:
            negative_yield_detected = all(x.delta_h < -self.divergence_threshold for x in self.history[-self.negative_yield_window:])

        if negative_yield_detected:
            directive = "NEGATIVE_YIELD"
        elif (step_index >= self.minimum_steps_before_convergence and H < self.confidence_threshold and utility_gain < self.utility_epsilon):
            directive = "OPTIMAL_CONVERGENCE"
        elif len(self.history) >= self.stagnation_window:
            if all(abs(x.delta_h) < self.entropy_delta_threshold for x in self.history[-self.stagnation_window:]):
                directive = "IRREDUCIBLE_UNCERTAINTY"

        loss_avoided = 0
        if directive == "NEGATIVE_YIELD":
            loss_avoided = self.best_utility - utility

        return directive, loss_avoided