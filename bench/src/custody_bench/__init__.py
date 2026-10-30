"""AgentDojo harness for evaluating mcp-custody.

Tool state lives in the server process, so a call that a gateway blocks can never change
what gets scored.
"""
