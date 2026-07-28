class EpistemicKernel:
    def __init__(self, gamma=0.95, patience=1, lam=2.5, window_k=10):
        self.gamma = gamma
        self.patience = patience
        self.lam = lam
        self.window_k = window_k
        self.entropy_history = []
        self.patience_counter = 0

    def step(self, h_current, h_previous, omega, dA):
        self.entropy_history.append(h_current)

        nri = 0
        tau_t = 0
        probe_triggered = False
        halt_execution = False

        # Simple thresholding logic based on recent entropy spikes
        if len(self.entropy_history) > self.window_k:
            baseline = sum(self.entropy_history[-self.window_k:-1]) / (self.window_k - 1)
            if h_current > baseline * self.lam:
                self.patience_counter += 1
                if self.patience_counter >= self.patience:
                    halt_execution = True
            else:
                self.patience_counter = 0

        return nri, tau_t, probe_triggered, halt_execution
