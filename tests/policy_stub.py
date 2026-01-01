from __future__ import annotations

from dbl_policy import DecisionOutcome, PolicyDecision, PolicyId, PolicyVersion, TenantId


class AllowPolicy:
    def evaluate(self, context):
        return PolicyDecision(
            outcome=DecisionOutcome.ALLOW,
            reason_code="ok",
            policy_id=PolicyId("test"),
            policy_version=PolicyVersion("1"),
            tenant_id=TenantId(context.tenant_id.value),
        )


policy = AllowPolicy()
