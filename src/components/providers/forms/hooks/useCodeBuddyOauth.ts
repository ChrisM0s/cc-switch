import { useManagedAuth } from "./useManagedAuth";

/**
 * CodeBuddy OAuth（腾讯云 CodeBuddy）认证 hook
 *
 * 复用通用 useManagedAuth，仅指定 provider 为 "codebuddy_oauth"
 */
export function useCodeBuddyOauth() {
  return useManagedAuth("codebuddy_oauth");
}
