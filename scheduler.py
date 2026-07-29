import math
import torch
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
        if not isinstance(value_of_information, (int, float)):
            raise TypeError("value_of_information must be a number")
        if value_of_information <= 0:
            raise ValueError("value_of_information must be positive")

        if not isinstance(divergence_threshold, (int, float)):
            raise TypeError("divergence_threshold must be a number")
        if divergence_threshold < 0:
            raise ValueError("divergence_threshold must be non-negative")

        if not isinstance(negative_yield_window, int):
            raise TypeError("negative_yield_window must be an integer")
        if negative_yield_window <= 0:
            raise ValueError("negative_yield_window must be positive")

        if not isinstance(entropy_delta_threshold, (int, float)):
            raise TypeError("entropy_delta_threshold must be a number")
        if entropy_delta_threshold < 0:
            raise ValueError("entropy_delta_threshold must be non-negative")

        if not isinstance(stagnation_window, int):
            raise TypeError("stagnation_window must be an integer")
        if stagnation_window <= 0:
            raise ValueError("stagnation_window must be positive")

        if not isinstance(confidence_threshold, (int, float)):
            raise TypeError("confidence_threshold must be a number")
        if confidence_threshold < 0:
            raise ValueError("confidence_threshold must be non-negative")

        if not isinstance(utility_epsilon, (int, float)):
            raise TypeError("utility_epsilon must be a number")
        if utility_epsilon < 0:
            raise ValueError("utility_epsilon must be non-negative")

        if not isinstance(minimum_steps_before_convergence, int):
            raise TypeError("minimum_steps_before_convergence must be an integer")
        if minimum_steps_before_convergence < 0:
            raise ValueError("minimum_steps_before_convergence must be non-negative")

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

    def entropy(self, probabilities):
        if not isinstance(probabilities, torch.Tensor):
            probabilities = torch.tensor(probabilities)

        if torch.any(probabilities < 0):
            raise ValueError("Probabilities cannot contain negative values")

        # Add epsilon to prevent log(0)
        probabilities = probabilities + 1e-9
        return -torch.sum(probabilities * torch.log2(probabilities)).item()

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

        utility = self.V * (self.initial_entropy - H) - self.total_cost

        utility_gain = 0
        if self.utility_history:
            utility_gain = utility - self.utility_history[-1]

        self.utility_history.append(utility)

        if utility > self.best_utility:
            self.best_utility = utility
            self.best_state = state
            self.best_step = step_index

        metric = StepMetrics(step_index, H, delta_h, eta, utility, utility_gain, state)
        self.history.append(metric)

        directive = "CONTINUE"
        negative_yield_detected = False
        if len(self.history) >= self.negative_yield_window:
            recent_delta = [x.delta_h for x in self.history[-self.negative_yield_window:]]
            negative_yield_detected = all(x < -self.divergence_threshold for x in recent_delta)

        if negative_yield_detected:
            directive = "NEGATIVE_YIELD"
        elif (step_index >= self.minimum_steps_before_convergence and H < self.confidence_threshold and utility_gain < self.utility_epsilon):
            directive = "OPTIMAL_CONVERGENCE"
        elif len(self.history) >= self.stagnation_window:
            recent = [abs(x.delta_h) for x in self.history[-self.stagnation_window:]]
            if all(x < self.entropy_delta_threshold for x in recent):
                directive = "IRREDUCIBLE_UNCERTAINTY"

        loss_avoided = 0
        if directive == "NEGATIVE_YIELD":
            loss_avoided = self.best_utility - utility

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
