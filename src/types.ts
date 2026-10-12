import type { ZodObject, ZodRawShape, ZodType } from "zod";

export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolExecutionPolicy {
  kind:
    | "compose-env-upsert"
    | "compose-deploy-exact"
    | "deployment-reconcile"
    | "super-password-status"
    | "env-keys"
    | "env-apply";
  maxAttempts: 1 | 3;
}

export interface ToolDefinition {
  name: string;
  description: string;
  tag: string;
  method: "GET" | "POST";
  path: string;
  schema: ZodObject<ZodRawShape>;
  annotations?: ToolAnnotations;
  execution?: ToolExecutionPolicy;
  outputSchema?: ZodType<unknown>;
}
