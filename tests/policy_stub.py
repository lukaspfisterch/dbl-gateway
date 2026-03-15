from __future__ import annotations

from dbl_policy.model import DecisionOutcome, PolicyDecision, PolicyId, PolicyVersion, TenantId


class AllowPolicy:
    policy_id = PolicyId("test")
    policy_version = PolicyVersion("1")

    def evaluate(self, context):
        return PolicyDecision(
            outcome=DecisionOutcome.ALLOW,
            reason_code="ok",
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            tenant_id=TenantId(context.tenant_id.value),
        )


policy = AllowPolicy()
