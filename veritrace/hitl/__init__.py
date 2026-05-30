"""Human-in-the-loop adapters."""

from .slack import (
    SlackApprovalError,
    SlackApprovalRegistry,
    SlackHITLApprover,
    verify_slack_signature,
)

__all__ = [
    "SlackApprovalError",
    "SlackApprovalRegistry",
    "SlackHITLApprover",
    "verify_slack_signature",
]
from .workflow import (
    ApprovalAuditLog, ApprovalRecord, ApproverChain, QuorumApprover,
    HITLWorkflowLayer, get_audit_log, _ApproverSlot,
)
