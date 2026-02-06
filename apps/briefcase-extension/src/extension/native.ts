const NATIVE_HOST = "com.briefcase.credential_briefcase";

export type NativeRequest = {
  id: string;
  method: string;
  params?: unknown;
};

export type NativeResponse = {
  id: string;
  ok: boolean;
  result?: unknown;
  error?: string;
};

function randomId(): string {
  // Stable-enough for correlating a request/response.
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export async function nativeCall<T = unknown>(
  method: string,
  params: unknown,
): Promise<T> {
  const req: NativeRequest = { id: randomId(), method, params };

  const resp = await new Promise<NativeResponse>((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, req, (r) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve(r as NativeResponse);
    });
  });

  if (resp.id !== req.id) {
    throw new Error("native messaging response id mismatch");
  }
  if (!resp.ok) {
    throw new Error(resp.error || "native messaging error");
  }
  return resp.result as T;
}

