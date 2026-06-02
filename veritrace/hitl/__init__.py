"""
veritrace.hitl
==============
Human-in-the-loop approval layer.

    SlackApprovalRegistry  — tracks pending approvals
    SlackHITLApprover      — async approver hook for HITLLayer
    verify_slack_signature — Slack request signature verification
    HITLWorkflowLayer      — escalation chains + quorum + audit log
    WebhookApprover / EmailNotifier / PagerDutyNotifier / CompositeApprover
                           — notification + approval adapters
"""
from .slack import (SlackApprovalError, SlackApprovalRegistry,
                    SlackHITLApprover, verify_slack_signature)
from .workflow import (ApprovalAuditLog, ApprovalRecord, ApproverChain,
                       HITLWorkflowLayer, QuorumApprover, get_audit_log)
from .adapters import (AdapterError, CompositeApprover, EmailNotifier,
                       PagerDutyNotifier, ServiceNowNotifier, SMTPConfig,
                       WebhookApprover)

__all__ = [
    "SlackApprovalError", "SlackApprovalRegistry", "SlackHITLApprover",
    "verify_slack_signature",
    "ApprovalAuditLog", "ApprovalRecord", "ApproverChain",
    "HITLWorkflowLayer", "QuorumApprover", "get_audit_log",
    "AdapterError", "CompositeApprover", "EmailNotifier",
    "PagerDutyNotifier", "ServiceNowNotifier", "SMTPConfig", "WebhookApprover",
]
