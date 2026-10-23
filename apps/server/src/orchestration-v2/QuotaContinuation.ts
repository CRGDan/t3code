import type {
  OrchestrationV2QuotaContinuationRefusal,
  OrchestrationV2ThreadProjection,
  RunId,
} from "@t3tools/contracts";
import {
  latestExecutedRun,
  latestRootProviderFailure,
} from "@t3tools/shared/orchestrationV2ThreadError";
import * as DateTime from "effect/DateTime";

import { threadShellFromProjection } from "./ProjectionStore.ts";

/**
 * Why a quota recovery continuation of `sourceRunId` may not start, or null
 * when it may. The dispatcher calls this under the thread's lock and checks
 * Stop itself. A continuation is only for a usage-limit failure that native
 * recovery cannot own, on the provider and model that failed, while no user
 * hold or newer work stands in its way.
 */
export function quotaContinuationRefusal(
  projection: OrchestrationV2ThreadProjection,
  sourceRunId: RunId,
  now: DateTime.Utc,
): OrchestrationV2QuotaContinuationRefusal | null {
  const { thread, runs } = projection;
  if (thread.archivedAt !== null || thread.deletedAt !== null) return "closed";
  if (thread.lineage.relationshipToParent === "subagent") return "subagent_thread";
  // A continuation cancelled before it started leaves the source latest again.
  if (runs.some((run) => run.quotaContinuationOfRunId === sourceRunId)) {
    return "already_continued";
  }
  const source = runs.find((run) => run.id === sourceRunId);
  if (source?.status !== "failed" || latestExecutedRun(runs)?.id !== source.id) {
    return "not_latest_failure";
  }
  const shell = threadShellFromProjection(projection);
  const failure = latestRootProviderFailure(source, projection.turnItems);
  if (failure?.class !== "usage_limit" || shell.lastErrorClass !== "usage_limit") {
    return "not_usage_limit";
  }
  // Native recovery owns a readable reset later than the failure, due or not.
  // The same comparison selects its candidates in UsageLimitRecoveryWorker.
  const resetMs = Date.parse(failure.resetAt ?? "");
  if (
    Number.isFinite(resetMs) &&
    resetMs > DateTime.toEpochMillis(source.completedAt ?? thread.updatedAt)
  ) {
    return "native_recovery";
  }
  if (
    thread.providerInstanceId !== source.providerInstanceId ||
    thread.modelSelection.instanceId !== source.modelSelection.instanceId ||
    thread.modelSelection.model !== source.modelSelection.model
  ) {
    return "model_changed";
  }
  if (thread.limitRecovery?.runId === source.id && !thread.limitRecovery.autoResume) {
    return "opted_out";
  }
  if (thread.settledOverride === "settled" || thread.settledAt !== null) return "settled";
  if (
    thread.snoozedUntil != null &&
    DateTime.toEpochMillis(thread.snoozedUntil) > DateTime.toEpochMillis(now)
  ) {
    return "snoozed";
  }
  if (shell.pendingRuntimeRequest !== null) return "pending_request";
  if (runs.some((run) => run.status === "queued" && run.queueHeld === true)) return "queue_held";
  return null;
}
