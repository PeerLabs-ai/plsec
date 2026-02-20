"""Tests for tool checking and dependency management (core/tools.py).

Covers version comparison logic, Tool/ToolChecker data structures,
and the REQUIRED_TOOLS/OPTIONAL_TOOLS module-level constants.
"""

from plsec.core.tools import (
    OPTIONAL_TOOLS,
    REQUIRED_TOOLS,
    Tool,
    ToolChecker,
    ToolStatus,
)


class TestVersionComparison:
    """Tests for ToolChecker._version_gte static method.

    This is a pure function with no side effects - ideal for unit testing.
    """

    def test_equal_versions(self):
        assert ToolChecker._version_gte("1.2.3", "1.2.3") is True

    def test_greater_patch(self):
        assert ToolChecker._version_gte("1.2.4", "1.2.3") is True

    def test_greater_minor(self):
        assert ToolChecker._version_gte("1.3.0", "1.2.9") is True

    def test_greater_major(self):
        assert ToolChecker._version_gte("2.0.0", "1.9.9") is True

    def test_less_than(self):
        assert ToolChecker._version_gte("1.2.0", "1.2.3") is False

    def test_short_version_padded(self):
        """A two-segment version should be compared as x.y.0."""
        assert ToolChecker._version_gte("1.2", "1.2.0") is True
        assert ToolChecker._version_gte("1.2.0", "1.2") is True

    def test_non_numeric_returns_true(self):
        """Non-numeric version strings should return True (fail-open)."""
        assert ToolChecker._version_gte("abc", "1.0.0") is True

    def test_extra_segments_truncated(self):
        """Only the first 3 segments should be compared."""
        assert ToolChecker._version_gte("1.2.3.4", "1.2.3") is True


class TestToolDataclass:
    """Tests for the Tool dataclass construction and defaults."""

    def test_required_fields(self):
        """Tool requires name and command at minimum."""
        tool = Tool(name="Test", command="test-cmd")
        assert tool.name == "Test"
        assert tool.command == "test-cmd"
        assert tool.required is True

    def test_default_status_is_missing(self):
        """A freshly constructed Tool should have MISSING status."""
        tool = Tool(name="Test", command="test-cmd")
        assert tool.status == ToolStatus.MISSING

    def test_post_check_fields_are_none(self):
        """version, path, and error should be None before check."""
        tool = Tool(name="Test", command="test-cmd")
        assert tool.version is None
        assert tool.path is None
        assert tool.error is None


class TestToolChecker:
    """Tests for ToolChecker filtering methods.

    These test the pure filtering logic (get_missing, get_outdated,
    all_required_ok) using pre-set tool statuses, without calling
    check_tool or touching the filesystem.
    """

    def _make_tool(self, name: str, required: bool, status: ToolStatus) -> Tool:
        """Create a tool with a pre-set status for testing filters."""
        tool = Tool(name=name, command=name.lower(), required=required)
        tool.status = status
        return tool

    def test_get_missing_returns_required_missing_only(self):
        """get_missing should return only required tools with MISSING status."""
        tools = [
            self._make_tool("A", required=True, status=ToolStatus.MISSING),
            self._make_tool("B", required=True, status=ToolStatus.OK),
            self._make_tool("C", required=False, status=ToolStatus.MISSING),
        ]
        checker = ToolChecker(tools)
        missing = checker.get_missing()
        assert len(missing) == 1
        assert missing[0].name == "A"

    def test_get_outdated(self):
        """get_outdated should return tools with OUTDATED status."""
        tools = [
            self._make_tool("A", required=True, status=ToolStatus.OUTDATED),
            self._make_tool("B", required=True, status=ToolStatus.OK),
        ]
        checker = ToolChecker(tools)
        outdated = checker.get_outdated()
        assert len(outdated) == 1
        assert outdated[0].name == "A"

    def test_all_required_ok_true(self):
        """all_required_ok should return True when all required tools are OK."""
        tools = [
            self._make_tool("A", required=True, status=ToolStatus.OK),
            self._make_tool("B", required=False, status=ToolStatus.MISSING),
        ]
        checker = ToolChecker(tools)
        assert checker.all_required_ok() is True

    def test_all_required_ok_false(self):
        """all_required_ok should return False when any required tool is not OK."""
        tools = [
            self._make_tool("A", required=True, status=ToolStatus.OK),
            self._make_tool("B", required=True, status=ToolStatus.MISSING),
        ]
        checker = ToolChecker(tools)
        assert checker.all_required_ok() is False

    def test_check_nonexistent_tool(self):
        """check_tool with a tool not on PATH should set MISSING status."""
        tool = Tool(
            name="NonexistentTool",
            command="plsec-nonexistent-tool-12345",
            required=True,
        )
        checker = ToolChecker([tool])
        checker.check_all()
        assert tool.status == ToolStatus.MISSING


class TestToolConstants:
    """Tests for the module-level REQUIRED_TOOLS and OPTIONAL_TOOLS lists.

    These verify the constants are well-formed and non-empty, catching
    accidental deletion or malformation.
    """

    def test_required_tools_nonempty(self):
        assert len(REQUIRED_TOOLS) > 0

    def test_optional_tools_nonempty(self):
        assert len(OPTIONAL_TOOLS) > 0

    def test_all_tools_have_names_and_commands(self):
        """Every tool should have a non-empty name and command."""
        for tool in REQUIRED_TOOLS + OPTIONAL_TOOLS:
            assert tool.name, f"Tool missing name: {tool}"
            assert tool.command, f"Tool missing command: {tool}"

    def test_required_tools_have_install_hints(self):
        """Required tools should provide install hints for doctor output."""
        for tool in REQUIRED_TOOLS:
            assert tool.install_hint, f"{tool.name} missing install_hint"
