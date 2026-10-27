"""Shared simulator transport errors (independent of any conversation policy)."""


class SimulatorInfrastructureError(RuntimeError):
    """The environment could not produce a valid simulated-user response."""


class SimulatorProtocolError(SimulatorInfrastructureError):
    """Invalid provider output is evidence, never a successful control message."""

    def __init__(self, message: str, *, raw_response: str, reason: str):
        super().__init__(message)
        self.raw_response = raw_response
        self.reason = reason
