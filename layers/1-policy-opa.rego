# Layer 1. Pre execution policy enforcement.
# The agent asks this before every tool call. This file is identical on any
# platform, with any agent framework, against any model.
package agent.tools

default allow := false

# Investigation is always fine, including the shell. A real coding agent has one,
# and pretending otherwise just hides every layer below this one.
allow if input.tool in {"list_environments", "check_credentials", "read_file", "run_shell"}

# Destructive tools are fine anywhere that is not production.
# The policy resolves the service id to an environment. The agent never did.
allow if {
	input.tool == "reset_environment"
	input.target.env != "production"
}

# In production a human has to approve. A plain reply is enough:
# "approve", "yes", "go ahead".
allow if {
	input.tool == "reset_environment"
	valid_approval(input.approval)
}

# The shell is allowed on purpose. It is the path policy cannot reason about,
# so layers 2, 4, 5 and 6 are what stand behind it.

valid_approval(a) if {
	a != null
	contains(lower(a), "approve")
}

valid_approval(a) if {
	a != null
	contains(lower(a), "yes")
}
