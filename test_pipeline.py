from unittest.mock import MagicMock, patch
import pytest
import torch
from scheduler import DecisionResult

mock_model = MagicMock()
mock_tokenizer = MagicMock()

class MockTokenizerOutput:
    def __init__(self, input_ids):
        self.input_ids = input_ids
    def to(self, device):
        return self

def mock_tokenizer_call(prompt, return_tensors="pt"):
    return MockTokenizerOutput(torch.tensor([[101, 102, 103]]))

mock_tokenizer.side_effect = mock_tokenizer_call
mock_tokenizer.decode.return_value = " test"

class MockModelOutput:
    def __init__(self, logits, past_key_values):
        self.logits = logits
        self.past_key_values = past_key_values

def mock_model_call(input_ids, past_key_values=None, use_cache=True):
    batch = input_ids.shape[0]
    seq = input_ids.shape[1]
    vocab = 50257

    logits = torch.randn(batch, seq, vocab)
    logits[:, :, 42] = 100.0

    return MockModelOutput(logits=logits, past_key_values="dummy_past")

mock_model.side_effect = mock_model_call

mock_from_pretrained_model = MagicMock()
mock_from_pretrained_model.return_value.to.return_value = mock_model

mock_from_pretrained_tokenizer = MagicMock()
mock_from_pretrained_tokenizer.return_value = mock_tokenizer

# Patch transformers functions before pipeline is imported
with patch("transformers.AutoModelForCausalLM.from_pretrained", mock_from_pretrained_model), \
     patch("transformers.AutoTokenizer.from_pretrained", mock_from_pretrained_tokenizer):
    import pipeline

@pytest.fixture(autouse=True)
def setup_mocks():
    pipeline.tokenizer = mock_tokenizer
    pipeline.model = mock_model

def test_evaluate_eac_robust_happy_path():
    trace = pipeline.evaluate_eac_robust("test prompt", max_new_tokens=3)

    assert len(trace) == 3
    for step in trace:
        assert "step" in step
        assert "text" in step
        assert "entropy" in step
        assert "token_count" in step
        assert step["text"] == " test"

def test_evaluate_eac_robust_halt_condition():
    original_scheduler = pipeline.EntropyAwareScheduler

    class MockScheduler:
        def __init__(self):
            self.history = [
                MagicMock(state=" test", entropy=0.5),
                MagicMock(state=" test", entropy=0.5)
            ]
            self.step_calls = 0

        def step(self, probabilities, cost, state):
            self.step_calls += 1
            if self.step_calls == 1:
                return DecisionResult(
                    halt=False, directive="CONTINUE", best_state=" test", best_step=0,
                    best_utility=10.0, utility_loss_avoided=0.0, termination_step=0,
                    current_utility=10.0, peak_utility=10.0
                )
            else:
                return DecisionResult(
                    halt=True, directive="NEGATIVE_YIELD", best_state=" test", best_step=0,
                    best_utility=10.0, utility_loss_avoided=5.0, termination_step=1,
                    current_utility=5.0, peak_utility=10.0
                )

    with patch("pipeline.EntropyAwareScheduler", MockScheduler):
        trace = pipeline.evaluate_eac_robust("test prompt", max_new_tokens=10)

        assert len(trace) == 2
