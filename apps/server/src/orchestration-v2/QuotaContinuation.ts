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

export function quotaContinuationRefusal(
  projection: OrchestrationV2ThreadProjection,
  sourceRunId: RunId,
  now: DateTime.Utc,
): Exclude<OrchestrationV2QuotaContinuationRefusal, "stopped"> | null {
  const { thread, runs } = projection;
  if (thread.archivedAt !== null || thread.deletedAt !== null) return "closed";
  if (thread.lineage.relationshipToParent === "subagent") return "subagent_thread";
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
