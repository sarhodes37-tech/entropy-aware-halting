from epistemicos.engine import EpistemicOrchestrator
from epistemicos.gates import CryptoAttestationGate
crypto = CryptoAttestationGate()
crypto._check_ocsp_revocation = lambda x: False
# Actually wait... the dataset sets crypto to COMPROMISED
# The baseline includes crypto gate because it was registered inside _build_orchestrator
