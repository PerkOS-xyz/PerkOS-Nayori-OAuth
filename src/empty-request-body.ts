/** Adapter-created empty streams are allowed; no payload bytes are buffered or accepted. */
export async function requireEmptyRequestBody(request: Request): Promise<void> {
  const length = request.headers.get("content-length");
  if (length !== null && length !== "0") {
    void request.body?.cancel().catch(() => undefined);
    throw Error("invalid_request");
  }
  if (!request.body) return;
  const reader = request.body.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(Error("invalid_request")), 1000);
    });
    // Bound even pathological streams that yield endless empty chunks.
    for (let i = 0; i < 8; i++) {
      const chunk = await Promise.race([reader.read(), deadline]);
      if (chunk.done) return;
      if (chunk.value.byteLength !== 0) throw Error("invalid_request");
    }
    throw Error("invalid_request");
  } finally {
    clearTimeout(timer);
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
