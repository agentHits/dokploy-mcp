export interface FormattedResponse {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

export const ResponseFormatter = {
  success(message: string, data?: unknown): FormattedResponse {
    const responseData = {
      success: true,
      message,
      ...(data !== undefined && data !== null ? { data } : {}),
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(responseData, null, 2),
        },
      ],
    };
  },

  error(message: string, details?: string): FormattedResponse {
    const errorData = {
      success: false,
      error: message,
      ...(details && { details }),
    };

    return {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify(errorData, null, 2),
        },
      ],
    };
  },
};
