"""Metadata actions (id, phase, msg, severity, tag, etc.)."""

from __future__ import annotations

from ._base import (
    Action,
    ActionType,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)


@register_action("id")
class IdAction(Action):
    """ID action provides metadata about the rule."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """ID action requires an argument."""
        if not data:
            msg = "ID action requires an ID argument"
            raise ValueError(msg)
        try:
            self.rule_id = int(data)
        except ValueError as e:
            msg = f"ID must be a valid integer: {data}"
            raise ValueError(msg) from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # ID is metadata, no runtime behavior


@register_action("phase")
class PhaseAction(Action):
    """Phase action specifies when the rule should run."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Phase action requires a phase number."""
        if not data:
            msg = "Phase action requires a phase number"
            raise ValueError(msg)
        try:
            phase = int(data)
            if phase not in {1, 2, 3, 4, 5}:
                msg = f"Phase must be 1-5, got {phase}"
                raise ValueError(msg)
            self.phase = phase
        except ValueError as e:
            msg = f"Phase must be a valid integer 1-5: {data}"
            raise ValueError(msg) from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Phase is metadata, no runtime behavior


@register_action("msg")
class MsgAction(Action):
    """Message action provides a description for the rule."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Message action requires a message."""
        if not data:
            msg = "Message action requires a message"
            raise ValueError(msg)
        self.message = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Message is metadata, no runtime behavior


@register_action("severity")
class SeverityAction(Action):
    """Severity action specifies the rule severity."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Severity action requires a severity level."""
        if not data:
            msg = "Severity action requires a severity level"
            raise ValueError(msg)
        valid_severities = [
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "info",
            "high",
            "debug",
        ]
        if data.lower().strip("'") not in valid_severities:
            msg = f"Invalid severity '{data}', must be one of: {valid_severities}"
            raise ValueError(msg)
        self.severity = data.lower()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Severity is metadata, no runtime behavior


@register_action("tag")
class TagAction(Action):
    """Tag action for adding tags to rules."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Tag action requires a tag name."""
        if not data:
            msg = "Tag action requires a tag name"
            raise ValueError(msg)
        self.tag_name = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Tags are metadata only


@register_action("maturity")
class MaturityAction(Action):
    """Maturity action for rule maturity level."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Maturity action requires a maturity level."""
        if not data:
            msg = "Maturity action requires a maturity level"
            raise ValueError(msg)
        try:
            self.maturity = int(data)
        except ValueError as e:
            msg = f"Maturity must be an integer: {data}"
            raise ValueError(msg) from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Maturity is metadata only


@register_action("accuracy")
class AccuracyAction(Action):
    """Accuracy action for rule accuracy level."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Accuracy action requires an accuracy level."""
        if not data:
            msg = "Accuracy action requires an accuracy level"
            raise ValueError(msg)
        try:
            self.accuracy = int(data)
        except ValueError as e:
            msg = f"Accuracy must be an integer: {data}"
            raise ValueError(msg) from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Accuracy is metadata only


@register_action("logdata")
class LogDataAction(Action):
    """Log data action specifies what data to log."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """LogData action can have optional data specification."""
        self.log_data = data or ""

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Metadata only


@register_action("status")
class StatusAction(Action):
    """Status action for HTTP response status."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Status action requires a status code."""
        if not data:
            msg = "Status action requires a status code"
            raise ValueError(msg)
        try:
            self.status_code = int(data)
        except ValueError as e:
            msg = f"Status must be an integer: {data}"
            raise ValueError(msg) from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Status is metadata only


@register_action("rev")
class RevAction(Action):
    """Rev action specifies rule revision."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Rev action requires a revision number."""
        if not data:
            msg = "Rev action requires a revision number"
            raise ValueError(msg)
        self.revision = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Revision is metadata only


@register_action("ver")
class VerAction(Action):
    """Version action for rule compatibility checking.

    Specifies the minimum required version for rule compatibility.
    """

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Store version requirement."""
        if not data:
            msg = "Ver action requires version specification"
            raise ValueError(msg)
        self.required_version = data.strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Version checking is metadata only."""
