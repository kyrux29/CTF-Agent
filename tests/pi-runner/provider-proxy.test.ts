/** Proof that Pi's reviewed dispatcher routes HTTPS through its proxy. */

import { once } from "node:events";
import { createServer, type AddressInfo, type Server } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import { configureReviewedProviderEgress } from "../../services/pi-runner/src/provider-egress.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(async (server) => {
    server.close();
    await once(server, "close");
  }));
});

describe("live provider egress", () => {
  it("uses Pi's matching Undici dispatcher for an HTTPS model request", async () => {
    const received: string[] = [];
    const proxy = createServer((socket) => {
      socket.once("data", (data) => {
        received.push(data.toString("ascii"));
        // No upstream connection is made: the child only needs enough of a
        // response to prove Node routed the HTTPS request through this socket.
        socket.end("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
      });
    });
    servers.push(proxy);
    proxy.listen(0, "127.0.0.1");
    await once(proxy, "listening");
    const address = proxy.address() as AddressInfo;
    const originalHttpProxy = process.env.HTTP_PROXY;
    const originalHttpsProxy = process.env.HTTPS_PROXY;
    const originalNoProxy = process.env.NO_PROXY;
    process.env.HTTP_PROXY = `http://127.0.0.1:${address.port}`;
    process.env.HTTPS_PROXY = `http://127.0.0.1:${address.port}`;
    delete process.env.NO_PROXY;
    try {
      // The `.invalid` TLD is reserved. A direct fallback cannot reach a real
      // provider; the test passes only when the local proxy observes CONNECT.
      configureReviewedProviderEgress();
      await fetch("https://provider-proxy.test.invalid/v1/check").catch(() => undefined);
    } finally {
      if (originalHttpProxy === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = originalHttpProxy;
      if (originalHttpsProxy === undefined) delete process.env.HTTPS_PROXY;
      else process.env.HTTPS_PROXY = originalHttpsProxy;
      if (originalNoProxy === undefined) delete process.env.NO_PROXY;
      else process.env.NO_PROXY = originalNoProxy;
    }
    expect(received).toHaveLength(1);
    expect(received[0]).toMatch(
      /^CONNECT provider-proxy\.test\.invalid:443 HTTP\/1\.1\r\n/u,
    );
  });
});
