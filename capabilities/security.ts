import { Capability, a, containers } from "pepr";
import { V1SecurityContext, V1Container } from "@kubernetes/client-node";

export const SecurityPolicy = new Capability({
  name: "secuity-policy",
  description: "Security policies for pods",
  namespaces: ["secure-namespace"],
});

const { When } = SecurityPolicy;

/**
 * This policy ensures that Pods do not allow privilege escalation.
 *
 */
When(a.Pod)
  .IsCreatedOrUpdated()
  .Validate(request => {
    const violations = containers(request).filter(
      c =>
        c.securityContext?.allowPrivilegeEscalation === true ||
        c.securityContext?.privileged === true,
    );

    if (violations.length) {
      return request.Deny(
        securityContextMessage(
          "Privilege escalation is disallowed",
          ["allowPrivilegeEscalation = false", "privileged = false"],
          violations,
        ),
      );
    }

    return request.Approve();
  });

/**
 * Require Non-root User for Pods containers
 *
 */

When(a.Pod)
  .IsCreatedOrUpdated()
  .Mutate(request => {
    // Assign sane defaults to containers
    containers(request).forEach(c => {
      // Ensure the securityContext field is defined
      c.securityContext = c.securityContext || {};

      // Set the runAsNonRoot field to true if it is undefined
      if (c.securityContext.runAsNonRoot === undefined) {
        c.securityContext.runAsNonRoot = true;
      }

      // Set the runAsUser field to 1000 if it is undefined
      if (c.securityContext.runAsUser === undefined) {
        c.securityContext.runAsUser = 1000;
      }

      // Set the runAsGroup field to 1000 if it is undefined
      if (c.securityContext.runAsGroup === undefined) {
        c.securityContext.runAsGroup = 1000;
      }
    });

    const pod = request.Raw.spec!;

    // Ensure the securityContext field is defined
    pod.securityContext = pod.securityContext || {};

    // Set the runAsNonRoot field to true if it is undefined
    if (pod.securityContext.runAsNonRoot === undefined) {
      pod.securityContext.runAsNonRoot = true;
    }

    // Set the runAsUser field to 1000 if it is undefined
    if (pod.securityContext.runAsUser === undefined) {
      pod.securityContext.runAsUser = 1000;
    }

    // Set the runAsGroup field to 1000 if it is undefined
    if (pod.securityContext.runAsGroup === undefined) {
      pod.securityContext.runAsGroup = 1000;
    }
  })
  .Validate(request => {
    // Check if running as root by checking if runAsNonRoot is false or runAsUser is 0
    const isRoot = (ctx: Partial<V1SecurityContext>) => {
      const isRunAsRoot = ctx.runAsNonRoot === false;
      const isRunAsRootUser = ctx.runAsUser === 0;

      return isRunAsRoot || isRunAsRootUser;
    };

    // Check pod securityContext
    const podCtx = request.Raw.spec?.securityContext || {};
    if (isRoot(podCtx)) {
      return request.Deny(
        "Pod level securityContext does not meet the non-root user requirement.",
      );
    }

    // Check container securityContext
    const violations = containers(request).filter(c =>
      isRoot(c.securityContext),
    );

    if (violations.length) {
      return request.Deny(
        securityContextMessage(
          "Unauthorized container securityContext. Containers must not run as root",
          ["runAsNonRoot = false", "runAsUser > 0"],
          violations,
        ),
      );
    }

    return request.Approve();
  });

/**
 * Add sane CPU and Memory limits to containers
 *
 */
When(a.Pod)
  .IsCreatedOrUpdated()
  .Mutate(request => {
    containers(request).forEach(c => {
      // Ensure the resources field is defined
      c.resources = c.resources || {};

      if (c.resources.limits === undefined) {
        c.resources.limits = {
          cpu: "200m",
          memory: "256Mi",
        };
      }

      if (c.resources.requests === undefined) {
        c.resources.requests = {
          cpu: "100m",
          memory: "128Mi",
        };
      }
    });
  });

function securityContextMessage(
  msg: string,
  authorized: (string | undefined)[],
  ctx: V1Container[],
) {
  const violations = ctx.map(c => JSON.stringify(c)).join(" | ");
  const authMsg = authorized.filter(a => a).join(" | ");

  return `${msg}. Authorized: [${authMsg}] Found: ${violations}`;
}
