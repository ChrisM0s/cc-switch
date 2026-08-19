import { getVersion } from "@tauri-apps/api/app";

export type UpdateChannel = "stable" | "beta";

export interface UpdateInfo {
  currentVersion: string;
  availableVersion: string;
  notes?: string;
  pubDate?: string;
}

export interface CheckOptions {
  timeout?: number;
  channel?: UpdateChannel;
}

export async function getCurrentVersion(): Promise<string> {
  try {
    return await getVersion();
  } catch {
    return "";
  }
}

export async function checkForUpdate(
  opts: CheckOptions = {},
): Promise<
  { status: "up-to-date" } | { status: "available"; info: UpdateInfo }
> {
  // fork 定制：不检查上游源仓库版本，始终视为已是最新版本。
  // 如需恢复真实检查，取消下方注释并删除上面的 return。
  void opts;
  return { status: "up-to-date" };

  // ---- 原版实现（上游版本检查，fork 中已禁用） ----
  // // 动态引入，避免在未安装插件时导致打包期问题
  // const { check } = await import("@tauri-apps/plugin-updater");
  //
  // const currentVersion = await getCurrentVersion();
  // const update = await check({ timeout: opts.timeout ?? 30000 } as any);
  //
  // if (!update) {
  //   return { status: "up-to-date" };
  // }
  //
  // const info: UpdateInfo = {
  //   currentVersion,
  //   availableVersion: (update as any).version ?? "",
  //   notes: (update as any).notes,
  //   pubDate: (update as any).date,
  // };
  //
  // return { status: "available", info };
}
