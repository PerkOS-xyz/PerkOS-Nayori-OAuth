import { describe, expect, it, vi } from "vitest";
import { requireEmptyRequestBody } from "../src/empty-request-body.js";
const request = (body: ReadableStream<Uint8Array>, headers = {}) => new Request("http://localhost/test", {
  method: "POST", body, headers, duplex: "half",
} as RequestInit & { duplex: "half" });
describe("empty request body boundary", () => {
  it("allows null and completed empty streams", async () => {
    await requireEmptyRequestBody(new Request("http://localhost/test", { method: "POST" }));
    await requireEmptyRequestBody(request(new ReadableStream({ start(c) { c.close(); } })));
  });
  it("rejects bytes even when declared empty", async () => {
    await expect(requireEmptyRequestBody(request(new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); c.close(); } }), { "content-length": "0" }))).rejects.toThrow();
  });
  it("rejects declared content before reading", async () => {
    await expect(requireEmptyRequestBody(request(new ReadableStream(), { "content-length": "1" }))).rejects.toThrow();
  });
  it("bounds stalled bodies and cancels them", async () => {
    vi.useFakeTimers();
    try {
      const cancel = vi.fn();
      const pending = requireEmptyRequestBody(request(new ReadableStream({ cancel })));
      const rejected = expect(pending).rejects.toThrow();
      await vi.advanceTimersByTimeAsync(1001); await rejected; expect(cancel).toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });
  it("bounds endless empty chunks", async () => {
    await expect(requireEmptyRequestBody(request(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array()); } })))).rejects.toThrow();
  });
});
