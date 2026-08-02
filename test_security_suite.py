import json
import unittest
from epistemicos.core import EpistemicOrchestrator
from epistemicos.gates import EntropyGate, PermissionGate, CryptoAttestationGate, GateAction
from epistemicos.cpr import CanonicalProblemRepresentation

class TestSecuritySuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Initializes the Orchestrator and Gates once for the entire suite.
        """
        print("\n[+] Initializing EpistemicOS Security Suite...")
        priors = {"preferred": 0.5, "standard": 0.3, "substandard": 0.2}
        cls.os = EpistemicOrchestrator(prior_probabilities=priors)
        
        # Register the defense-in-depth gates
        cls.os.register_gate("EntropyGate", EntropyGate(z_threshold=2.85))
        cls.os.register_gate("PermissionGate", PermissionGate(contract_model=CanonicalProblemRepresentation))
        cls.os.register_gate("CryptoAttestationGate", CryptoAttestationGate(required_algorithm="ML-DSA", expiry_year=2030))

        # Load the unified commercial dataset
        cls.dataset = []
        with open("dataset_unified_commercial.jsonl", "r") as f:
            for line in f:
                if line.strip():
                    cls.dataset.append(json.loads(line))
        print(f"[+] Loaded {len(cls.dataset)} risk profiles for evaluation.")

    def test_pipeline_security_enforcement(self):
        """
        Validates that the orchestrator correctly COMMITs clean payloads 
        and ROLLBACKs adversarial/compromised payloads.
        """
        for case in self.dataset:
            # subTest ensures that if one payload fails, the suite continues testing the rest
            with self.subTest(case_id=case["id"], is_adversarial=case["is_adversarial"]):
                
                result = self.os.process_submission(
                    raw_payload=case["payload"],
                    likelihoods=case.get("likelihoods", {}),
                    token_logprobs=case["context"].get("token_logprobs", []),
                    proposed_actions=case["context"].get("proposed_actions", []),
                    crypto_metadata=case["context"].get("cryptography", {})
                )
                
                # Map internal GateActions to the benchmark's expected output
                actual_action = "COMMIT" if result["action"] == GateAction.ALLOW else "ROLLBACK"
                
                self.assertEqual(
                    actual_action, 
                    case["expected_action"], 
                    f"\nFailed on {case['id']}:\n"
                    f"Expected: {case['expected_action']}\n"
                    f"Actual: {actual_action}\n"
                    f"Receipt: {json.dumps(result['receipt'], indent=2)}"
                )

if __name__ == '__main__':
    unittest.main(verbosity=2)
