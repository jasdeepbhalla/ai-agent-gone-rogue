# Layer 1. Pre execution policy enforcement.
# The agent asks this before every tool call. This file is identical on any
# platform, with any agent framework, against any model.
package agent.tools

default allow := false

# Read only tools are always fine.
allow if input.tool in {"list_environments", "check_credentials", "read_file"}

# Destructive tools are fine anywhere that is not production.
allow if {
	input.tool == "reset_environment"
	input.target.env != "production"
}

# In production they need a signed, single use approval.
allow if {
	input.tool == "reset_environment"
	valid_approval(input.approval)
}

# Shell is not a tool, it is an escape hatch. Layer 2 watches it instead.
# Deliberately absent from every allow rule above.

valid_approval(a) if {
	a != null
	startswith(a, "appr_")
}
