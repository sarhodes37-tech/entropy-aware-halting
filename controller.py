class EpistemicController:
    def __init__(self, k_persistence=2, threshold=0.45):
        self.k_persistence = k_persistence
        self.threshold = threshold
        self.is_trained = False
