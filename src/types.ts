import type { ZodObject, ZodType } from "zod";

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
  schema: ZodObject<Record<string, ZodType>>;
  annotations?: ToolAnnotations;
  execution?: ToolExecutionPolicy;
  outputSchema?: ZodType<unknown>;
}
