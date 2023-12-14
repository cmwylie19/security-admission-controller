import { beforeAll, describe, expect, it } from "@jest/globals";
import { K8s, kind } from "pepr";

const failIfReached = () => expect(true).toBe(false);

describe("security policies", () => {
  beforeAll(async () => {
    await K8s(kind.Namespace).Apply({
      apiVersion: "v1",
      kind: "Namespace",
      metadata: {
        name: "secure-namespace",
      },
      spec: {},
    });
  });
  it("should not allow privilege escalation", async () => {
    const expected = (e: Error) =>
      expect(e).toMatchObject({
        ok: false,
        data: {
          message: expect.stringContaining(
            "Privilege escalation is disallowed. Authorized: [allowPrivilegeEscalation = false | privileged = false]",
          ),
        },
      });

    return Promise.all([
      // Check for allowPrivilegeEscalation
      K8s(kind.Pod)
        .Apply({
          metadata: {
            name: "security-privilege-escalation",
            namespace: "secure-namespace",
          },
          spec: {
            containers: [
              {
                name: "test",
                image: "127.0.0.1/fake",
                securityContext: {
                  allowPrivilegeEscalation: true,
                },
              },
            ],
          },
        })
        .then(failIfReached)
        .catch(expected),

      // Check for privileged
      K8s(kind.Pod)
        .Apply({
          metadata: {
            name: "security-privileged",
            namespace: "secure-namespace",
          },
          spec: {
            containers: [
              {
                name: "test",
                image: "127.0.0.1/fake",
                securityContext: {
                  privileged: true,
                },
              },
            ],
          },
        })
        .then(failIfReached)
        .catch(expected),
    ]);
  });

  it("should not allow root users", async () => {
    const expected = (e: Error) =>
      expect(e).toMatchObject({
        ok: false,
        data: {
          message: expect.stringContaining(
            "Unauthorized container securityContext. Containers must not run as root. Authorized: [runAsNonRoot = false | runAsUser > 0]",
          ),
        },
      });

    return Promise.all([
      // Check for runAsUser = 0
      K8s(kind.Pod)
        .Apply({
          metadata: {
            name: "security-run-as-user",
            namespace: "secure-namespace",
          },
          spec: {
            containers: [
              {
                name: "test",
                image: "127.0.0.1/fake",
                securityContext: {
                  runAsUser: 0,
                },
              },
            ],
          },
        })
        .then(failIfReached)
        .catch(expected),

      // Check for runAsNonRoot = false
      K8s(kind.Pod)
        .Apply({
          metadata: {
            name: "security-run-as-non-root",
            namespace: "secure-namespace",
          },
          spec: {
            containers: [
              {
                name: "test",
                image: "127.0.0.1/fake",
                securityContext: {
                  runAsNonRoot: false,
                },
              },
            ],
          },
        })
        .then(failIfReached)
        .catch(expected),

      // Check for runAsNonRoot = true and runAsUser = 0
      K8s(kind.Pod)
        .Apply({
          metadata: {
            name: "security-run-as-non-root-and-user",
            namespace: "secure-namespace",
          },
          spec: {
            containers: [
              {
                name: "test",
                image: "127.0.0.1/fake",
                securityContext: {
                  runAsNonRoot: false,
                  runAsUser: 0,
                },
              },
            ],
          },
        })
        .then(failIfReached)
        .catch(expected),
    ]);
  });
});
