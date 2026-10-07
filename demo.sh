#!/usr/bin/env bash
# demo.sh — one command to get the live demo ready.
#
# Nothing account specific is stored here. The instance is discovered from the
# CloudFormation stack at runtime, so this file is safe to commit and share.
#
#   ./demo.sh up         start tunnels, wait until live, open dashboard + Jaeger
#   ./demo.sh incident   run part one (vulnerable): the agent goes off the rails
#   ./demo.sh rebuild    run part two (hardened): the six layers hold
#   ./demo.sh reset      reseed data and return to vulnerable mode
#   ./demo.sh status     rows, backups, current mode
#   ./demo.sh try-delete  (hardened) try the delete by hand as root; the engine refuses
#   ./demo.sh logs       tail agent + OPA + Falco
#   ./demo.sh connect    open an interactive shell on the box
#   ./demo.sh down       close the tunnels
#
set -euo pipefail

STACK="${STACK:-ai-agent-gone-rogue}"
REGION="${REGION:-us-west-2}"
DASH_PORT="${DASH_PORT:-8080}"      # localhost port for the dashboard
JAEGER_PORT="${JAEGER_PORT:-16687}" # localhost port for Jaeger (distinct from the
                                    # remote 16686 on purpose — reusing the same
                                    # number collides with stale tunnels)
RUNDIR="${TMPDIR:-/tmp}/ai-agent-gone-rogue-demo"
mkdir -p "$RUNDIR"

c()  { printf '\033[1;36m%s\033[0m\n' "$*"; }   # cyan heading
ok() { printf '\033[1;32m%s\033[0m\n' "$*"; }   # green
die(){ printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing: $1  ($2)"; }
preflight() {
  need aws "install the AWS CLI v2"
  session-manager-plugin >/dev/null 2>&1 || \
    die "missing: session-manager-plugin  (https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)"
}

iid() {
  # Discover the EC2 instance from the stack. No hardcoded id.
  local id
  id=$(aws cloudformation describe-stack-resources --stack-name "$STACK" --region "$REGION" \
        --query "StackResources[?ResourceType=='AWS::EC2::Instance'].PhysicalResourceId" \
        --output text 2>/dev/null | head -n1)
  [ -n "$id" ] && [ "$id" != "None" ] || die "no instance found in stack '$STACK' ($REGION). Is it deployed?"
  echo "$id"
}

# run a command on the box and print its output
remote() {
  local IID cmd_id out
  IID=$(iid)
  cmd_id=$(aws ssm send-command --instance-ids "$IID" --region "$REGION" \
    --document-name AWS-RunShellScript \
    --parameters "commands=[\"cd /opt/ai-agent-gone-rogue && $1\"]" \
    --query Command.CommandId --output text)
  # wait for it to finish
  for _ in $(seq 1 30); do
    sleep 2
    out=$(aws ssm get-command-invocation --command-id "$cmd_id" --instance-id "$IID" \
          --region "$REGION" --query '{S:Status,O:StandardOutputContent,E:StandardErrorContent}' \
          --output json 2>/dev/null) || continue
    case "$(echo "$out" | sed -n 's/.*"S": *"\([^"]*\)".*/\1/p')" in
      Success)  echo "$out" | python3 -c 'import sys,json;print(json.load(sys.stdin)["O"].rstrip())'; return 0;;
      Failed|Cancelled|TimedOut) echo "$out" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["O"]);print(d["E"],file=sys.stderr)'; return 1;;
    esac
  done
  die "remote command timed out"
}

tunnel() {  # remote_port local_port name
  local IID; IID=$(iid)
  nohup aws ssm start-session --target "$IID" --region "$REGION" \
    --document-name AWS-StartPortForwardingSession \
    --parameters "{\"portNumber\":[\"$1\"],\"localPortNumber\":[\"$2\"]}" \
    >"$RUNDIR/$3.log" 2>&1 &
  echo $! > "$RUNDIR/$3.pid"
}

wait_ready() {  # local_port label
  printf 'waiting for %s on localhost:%s ' "$2" "$1"
  for _ in $(seq 1 30); do
    if curl -s -o /dev/null -m 2 "http://localhost:$1/"; then echo; ok "  $2 ready → http://localhost:$1"; return 0; fi
    printf '.'; sleep 1
  done
  echo; die "$2 did not come up on localhost:$1 — check $RUNDIR"
}

open_url() { command -v open >/dev/null 2>&1 && open "$1" >/dev/null 2>&1 || true; }

free_port() {  # kill anything already listening on a local port (stale tunnel)
  local pids; pids=$(lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null || true)
  [ -n "$pids" ] && kill $pids 2>/dev/null || true
}

teardown() {
  for name in dashboard jaeger; do
    [ -f "$RUNDIR/$name.pid" ] && { kill "$(cat "$RUNDIR/$name.pid")" 2>/dev/null || true; rm -f "$RUNDIR/$name.pid"; }
  done
  free_port "$DASH_PORT"; free_port "$JAEGER_PORT"
}

case "${1:-up}" in
  up)
    preflight
    c "==> discovering instance in stack '$STACK' ($REGION)"; ok "    $(iid)"
    c "==> clearing any stale tunnels"; teardown
    c "==> opening tunnels"
    tunnel 80 "$DASH_PORT" dashboard
    tunnel 16686 "$JAEGER_PORT" jaeger
    wait_ready "$DASH_PORT" "dashboard"
    wait_ready "$JAEGER_PORT" "jaeger"
    # Open the two demo tabs only. Jaeger stays tunnelled (localhost:$JAEGER_PORT)
    # but is not opened automatically.
    open_url "http://localhost:$DASH_PORT/vulnerable"
    open_url "http://localhost:$DASH_PORT/hardened"
    echo
    ok "READY. Vulnerable and Hardened tabs are open in your browser."
    echo "   Jaeger (if you want it): http://localhost:$JAEGER_PORT"
    echo "Next:  ./demo.sh incident   then   ./demo.sh rebuild"
    echo "When done:  ./demo.sh down"
    ;;

  incident)
    c "==> vulnerable mode"; remote "./rogue mode vulnerable"
    c "==> sending the prompt — WATCH THE DASHBOARD"; remote "./rogue demo"
    ok "Running. The agent is working now; watch it on localhost:$DASH_PORT."
    ;;

  rebuild)
    c "==> reseeding"; remote "./rogue seed"
    c "==> hardened mode (six layers on)"; remote "./rogue mode hardened"
    c "==> sending the same prompt — WATCH THE DASHBOARD"; remote "./rogue demo"
    ok "Running. This time the layers hold; watch it on localhost:$DASH_PORT."
    ;;

  reset)
    # vulnerable first: it drops the deletion-protection trigger, or the reseed's
    # table drop would be refused when coming from hardened.
    c "==> vulnerable mode + reseeding"; remote "./rogue mode vulnerable && ./rogue seed"
    ok "Back to a clean starting point."
    ;;

  status) remote "./rogue status" ;;
  try-delete)
    c "==> trying the delete by hand as the database master (root), in hardened mode"
    remote "./rogue try-delete"
    ;;
  logs)   c "Ctrl-C to stop"; IID=$(iid); aws ssm start-session --target "$IID" --region "$REGION" \
            --document-name AWS-StartInteractiveCommand \
            --parameters '{"command":["cd /opt/ai-agent-gone-rogue && ./rogue logs"]}' ;;

  connect)
    IID=$(iid)
    ok "Opening a shell. Run:  cd /opt/ai-agent-gone-rogue  then  ./rogue demo"
    aws ssm start-session --target "$IID" --region "$REGION" ;;

  down)
    c "==> closing tunnels"; teardown
    ok "Tunnels closed. Nothing is exposed."
    ;;

  *) grep '^#' "$0" | sed '1d;s/^# \{0,1\}//'; exit 1 ;;
esac
