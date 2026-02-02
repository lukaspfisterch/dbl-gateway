from __future__ import annotations


class RaisePolicy:
    def evaluate(self, context):
        raise RuntimeError("policy evaluation failed")


policy = RaisePolicy()
