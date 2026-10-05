# Layer 3. Structured audit logging.
# Excerpt from agent.py (the full file is embedded in deploy.yaml).
# Every tool call, every policy decision, every result becomes a span in Jaeger.
# When something goes wrong, this is the flight recorder.

trace.set_tracer_provider(TracerProvider(resource=Resource.create({"service.name": "gone-rogue-agent"})))
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint=E.get("OTLP", "http://jaeger:4317"), insecure=True)))
tracer = trace.get_tracer("agent")


# Every policy decision is a span, with the verdict on it.
def policy_allows(tool: str, args: dict) -> tuple[bool, str]:
    ...
    with tracer.start_as_current_span("policy.decision") as sp:
        sp.set_attribute("policy.tool", tool)
        allow = requests.post(OPA_URL, json=payload, timeout=3).json().get("result", False)
        sp.set_attribute("policy.allow", bool(allow))
    ...


# Every tool the model invokes is a span: name, arguments, and result.
with tracer.start_as_current_span("agent.task") as task:
    task.set_attribute("agent.mode", mode())
    for u in uses:
        name, args = u["name"], u.get("input", {})
        with tracer.start_as_current_span(f"tool.{name}") as sp:
            sp.set_attribute("tool.name", name)
            sp.set_attribute("tool.args", json.dumps(args)[:500])
            ok, rule = policy_allows(name, args)
            res = TOOLS[name](**args) if ok else {"error": "DENIED_BY_POLICY", "rule": rule}
            sp.set_attribute("tool.result", json.dumps(res)[:500])
