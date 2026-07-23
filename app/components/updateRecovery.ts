export type PendingUpdateIdentity = {
  candidateCommit: string;
  releaseTag: string;
};

export type UpdateOperationIdentity = {
  state: "idle" | "applying" | "updated" | "failed";
  release_tag: string | null;
  applied_commit: string | null;
};

export function operationMatchesPending(
  operation: UpdateOperationIdentity,
  pending: PendingUpdateIdentity,
): boolean {
  if (operation.release_tag !== pending.releaseTag) return false;
  return operation.state === "updated"
    ? operation.applied_commit === pending.candidateCommit
    : operation.state === "applying" || operation.state === "failed";
}
