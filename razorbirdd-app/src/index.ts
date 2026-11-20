export { Spine } from "./spine";

interface Env {
  SPINE: DurableObjectNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "razorbirdd-spine" });
    }

    // One object holds the whole spine in this build. ?shard=<name> splits
    // tenants while developing, without changing any client code.
    const shard = url.searchParams.get("shard") ?? "main";
    return env.SPINE.get(env.SPINE.idFromName(shard)).fetch(request);
  },
};