"""Independent verifier contracts and a declarative local acceptance runner."""

from .m5_replay import (
    TECHNIQUE_LABS,
    TRUSTED_LABS,
    LabControllerClient,
    M5ReplayVerifier,
    M5VerificationWork,
    VerificationProcessingError,
)
from .remote_replay import (
    RemoteReplayOutcome,
    RemoteReplayVerifier,
    RemoteVerificationWork,
    remote_origin_digest,
    remote_work_from_wire,
)
from .service import (
    DeclarativeExploitPlan,
    IndependentVerifier,
    ReplayObservation,
    TargetReplayDriver,
    VerificationResult,
    mask_flag,
)

__all__ = [
    "DeclarativeExploitPlan",
    "IndependentVerifier",
    "LabControllerClient",
    "M5ReplayVerifier",
    "M5VerificationWork",
    "RemoteReplayOutcome",
    "RemoteReplayVerifier",
    "RemoteVerificationWork",
    "ReplayObservation",
    "TargetReplayDriver",
    "TECHNIQUE_LABS",
    "TRUSTED_LABS",
    "VerificationProcessingError",
    "VerificationResult",
    "mask_flag",
    "remote_origin_digest",
    "remote_work_from_wire",
]
