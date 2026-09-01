export type JsonObject = Record<string, unknown>;

export type Resource = JsonObject & { id: string };

export type ApiError = {
  status: number;
  message: string;
  requestId?: string;
  code?: string;
};

export type ApiResult<T> = { data?: T; error?: ApiError };

export type Operation = {
  id: string;
  status: string;
  plan_hash?: string;
  request_id?: string;
  [key: string]: unknown;
};

export type OperationEvent = {
  operation_id: string;
  sequence: number;
  status: string;
  message?: string;
  progress?: number;
};

export type FileEntry = {
  path: string;
  size: number;
  digest: string;
  classification: string;
};

export type FileRead = {
  path: string;
  content_type: string;
  content: number[];
};

export type FileDiff = {
  path: string;
  before_digest?: string;
  after_digest?: string;
  changed: boolean;
};
