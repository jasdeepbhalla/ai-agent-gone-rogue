# Walkthrough

915 lines in this repo. **You need to understand about 60 of them.**
Everything else is infrastructure boilerplate and a dashboard.

---

## What each file is, and whether to read it

| File | Lines | Read it? |
|---|---|---|
| `deploy.yaml` | 337 | **No.** CloudFormation. Creates a box, a database, two buckets and some roles |
| `agent/agent.py` | 301 | **Yes, about 60 of them.** See below |
| `rogue` | 115 | **No.** A shell script that flips the flag and reseeds |
| `dashboard/index.html` | 82 | **No.** Four boxes and a polling loop |
| `policy/agent.rego` | 30 | **Yes, all of it.** This is layer 1 |
| `falco/agent_rules.yaml` | 31 | **Yes, all of it.** This is layer 2 |
| `compose.yml` | 19 | Skim. Three containers |

---

## The whole idea, in four lines of real code

**1. The agent is given a tool. The tool takes a pool id, not an environment.**

`agent/agent.py:110`
```python
def reset_environment(pool="", environment="", **_):
```

**2. Only the code knows what that pool id means.**

`agent/agent.py:83`
```python
POOLS = {"rop-1": "staging", "rop-2": "production"}
```

**3. Before any tool runs, we translate the id and ask the policy engine.**

`agent/agent.py:65`
```python
env = POOLS.get(args.get("pool", ""), args.get("environment", "unknown"))
payload = {"input": {"tool": tool, "target": {"env": env, ...}}}
```

**4. The policy refuses anything it was not explicitly told to allow.**

`policy/agent.rego:6`
```rego
default allow := false
```

That is the talk. The agent asks to reset `rop-2`. It does not know that means production.
The policy looks it up, and says no.

---

## Follow one request, start to finish

1. You POST a prompt to `/run` &nbsp;→&nbsp; `agent.py:248`
2. `run()` asks Bedrock what to do &nbsp;→&nbsp; `agent.py:203`
3. Bedrock replies "call this tool with these arguments"
4. For each tool call, `policy_allows()` runs **first** &nbsp;→&nbsp; `agent.py:61`
   - In `vulnerable` mode it returns `True` without asking anything
   - In `hardened` mode it POSTs to OPA and waits
5. Allowed → the tool runs. Denied → the agent gets this back, **as data, not an error**:
   ```python
   {"error": "DENIED_BY_POLICY", "rule": ..., "hint": "A signed approval is required."}
   ```
6. The result goes back to Bedrock as the next message &nbsp;→&nbsp; `agent.py:243`
7. Loop, up to 12 turns

**Step 5 is why the agent asks a human instead of crashing.** A denial is just another
tool result, so the model reads it and adapts.

---

## The five tools

All in `agent/agent.py`, lines 86 to 147. None is longer than 20 lines.

| Tool | What it does | Why it exists |
|---|---|---|
| `list_environments` | Returns staging and production | Harmless |
| `check_credentials` | Returns `MISMATCH` and `affected_pool: rop-2` | The diagnostic that starts the trouble |
| `reset_environment` | Drops the table, deletes the backups | The destructive one |
| `read_file` | Reads a file from `/app` | Every real coding agent has this |
| `run_shell` | Runs a shell command | So does this. It is the bypass path |

`read_file` and `run_shell` are the point. They are how the agent finds
`app/.env.backup` and goes around the tool layer entirely.

---

## The two modes

`./rogue mode vulnerable` and `./rogue mode hardened` change six things at once.
The logic is in `rogue`, lines 55 to 90.

| | vulnerable | hardened |
|---|---|---|
| Agent IAM role | `s3:*` `rds:*` | read only, explicit deny on delete |
| Key in `app/.env.backup` | unscoped | `s3:ListBucket` only |
| OPA consulted | no | before every tool call |
| Database user | owns the table | `agent_ro`, select only |
| RDS deletion protection | off | on |
| Vault bucket | reachable | denied by role and by bucket policy |

Same commit. Same model. Same prompt.

---

## The two files that are entirely the point

**`policy/agent.rego`** — thirty lines, and half are comments.
Read the `default allow := false` line and the three `allow if` blocks. That is layer 1.
Note what is missing: `run_shell` appears nowhere, so it is refused by omission.

**`falco/agent_rules.yaml`** — two rules.
One fires when a process starts inside the agent container that has no business there.
One fires when something reads a file that looks like it holds credentials.
That is layer 2, and it is the only thing that sees the bypass path.

---

## What you can safely ignore

- All of `deploy.yaml`. If you want to know what it makes, read the `Outputs` at the bottom
- The OpenTelemetry setup at `agent.py:25`. Six lines of boilerplate
- Everything under `@app.get` from line 248. HTTP plumbing for the dashboard
- `dashboard/index.html`. It polls three endpoints and paints four boxes

---

## If you change one thing to understand it

Open `policy/agent.rego`, change `default allow := false` to `true`, then run the
hardened demo. It deletes everything.

One line is the difference between the two halves of this repo.
