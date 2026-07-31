import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Loader2,
  LogOut,
  ExternalLink,
  Plus,
  X,
  Sparkles,
  User,
} from "lucide-react";
import { useCodeBuddyOauth } from "./hooks/useCodeBuddyOauth";

interface CodeBuddyOAuthSectionProps {
  className?: string;
  /** 当前选中的 CodeBuddy 账号 ID */
  selectedAccountId?: string | null;
  /** 账号选择回调 */
  onAccountSelect?: (accountId: string | null) => void;
}

/**
 * CodeBuddy OAuth 认证区块
 *
 * 通过 CodeBuddy 官方登录流程（浏览器授权 + 轮询）登录 CodeBuddy 账号，
 * 用于将 Claude Code 请求反代到 CodeBuddy 官方 API。
 */
export const CodeBuddyOAuthSection: React.FC<CodeBuddyOAuthSectionProps> = ({
  className,
  selectedAccountId,
  onAccountSelect,
}) => {
  const { t } = useTranslation();

  const {
    accounts,
    defaultAccountId,
    hasAnyAccount,
    pollingState,
    deviceCode,
    error,
    isPolling,
    isAddingAccount,
    isRemovingAccount,
    isSettingDefaultAccount,
    startAuthWithCodebuddyOptions,
    removeAccount,
    setDefaultAccount,
    cancelAuth,
    logout,
  } = useCodeBuddyOauth();

  const [siteType, setSiteType] = useState<
    "international" | "china" | "enterprise"
  >("international");
  const [apiEndpoint, setApiEndpoint] = useState("");
  const [enterpriseId, setEnterpriseId] = useState("");
  const [userAgent, setUserAgent] = useState("");

  const handleAddAccount = () => {
    startAuthWithCodebuddyOptions({
      siteType,
      apiEndpoint:
        siteType === "enterprise" ? apiEndpoint : undefined,
      enterpriseId:
        siteType === "enterprise" ? enterpriseId : undefined,
      userAgent:
        siteType === "enterprise" && userAgent ? userAgent : undefined,
    });
  };

  const handleAccountSelect = (value: string) => {
    onAccountSelect?.(value === "none" ? null : value);
  };

  const handleRemoveAccount = (accountId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    removeAccount(accountId);
    if (selectedAccountId === accountId) {
      onAccountSelect?.(null);
    }
  };

  return (
    <div className={`space-y-4 ${className || ""}`}>
      {/* 认证状态标题 */}
      <div className="flex items-center justify-between">
        <Label>{t("codebuddyOauth.authStatus", "认证状态")}</Label>
        <Badge
          variant={hasAnyAccount ? "default" : "secondary"}
          className={hasAnyAccount ? "bg-green-500 hover:bg-green-600" : ""}
        >
          {hasAnyAccount
            ? t("codebuddyOauth.accountCount", {
                count: accounts.length,
                defaultValue: `${accounts.length} 个账号`,
              })
            : t("codebuddyOauth.notAuthenticated", "未认证")}
        </Badge>
      </div>

      {/* 账号选择器 */}
      {hasAnyAccount && onAccountSelect && (
        <div className="space-y-2">
          <Label className="text-sm text-muted-foreground">
            {t("codebuddyOauth.selectAccount", "选择账号")}
          </Label>
          <Select
            value={selectedAccountId || "none"}
            onValueChange={handleAccountSelect}
          >
            <SelectTrigger>
              <SelectValue
                placeholder={t(
                  "codebuddyOauth.selectAccountPlaceholder",
                  "选择一个 CodeBuddy 账号",
                )}
              />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">
                <span className="text-muted-foreground">
                  {t("codebuddyOauth.useDefaultAccount", "使用默认账号")}
                </span>
              </SelectItem>
              {accounts.map((account) => (
                <SelectItem key={account.id} value={account.id}>
                  <div className="flex items-center gap-2">
                    <User className="h-4 w-4 text-muted-foreground" />
                    <span>{account.login}</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {/* 已登录账号列表 */}
      {hasAnyAccount && (
        <div className="space-y-2">
          <Label className="text-sm text-muted-foreground">
            {t("codebuddyOauth.loggedInAccounts", "已登录账号")}
          </Label>
          <div className="space-y-1">
            {accounts.map((account) => (
              <div
                key={account.id}
                className="flex items-center justify-between p-2 rounded-md border bg-muted/30"
              >
                <div className="flex items-center gap-2">
                  <User className="h-5 w-5 text-muted-foreground" />
                  <span className="text-sm font-medium">{account.login}</span>
                  {defaultAccountId === account.id && (
                    <Badge variant="secondary" className="text-xs">
                      {t("codebuddyOauth.defaultAccount", "默认")}
                    </Badge>
                  )}
                  {selectedAccountId === account.id && (
                    <Badge variant="outline" className="text-xs">
                      {t("codebuddyOauth.selected", "已选中")}
                    </Badge>
                  )}
                </div>
                <div className="flex items-center gap-1">
                  {defaultAccountId !== account.id && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-xs text-muted-foreground"
                      onClick={() => setDefaultAccount(account.id)}
                      disabled={isSettingDefaultAccount}
                    >
                      {t("codebuddyOauth.setAsDefault", "设为默认")}
                    </Button>
                  )}
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-muted-foreground hover:text-red-500"
                    onClick={(e) => handleRemoveAccount(account.id, e)}
                    disabled={isRemovingAccount}
                    title={t("codebuddyOauth.removeAccount", "移除账号")}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 站点类型选择 */}
      {pollingState === "idle" && (
        <div className="space-y-3">
          <Label>{t("codebuddyOauth.selectSite", "选择站点")}</Label>
          <div className="grid grid-cols-3 gap-2">
            {(["international", "china", "enterprise"] as const).map(
              (type) => {
                const labels: Record<string, string> = {
                  international: t(
                    "codebuddyOauth.international",
                    "国际站",
                  ),
                  china: t("codebuddyOauth.china", "中国站"),
                  enterprise: t("codebuddyOauth.enterprise", "企业版"),
                };
                const hints: Record<string, string> = {
                  international: "codebuddy.ai",
                  china: "codebuddy.cn",
                  enterprise: "自托管",
                };
                return (
                  <button
                    key={type}
                    type="button"
                    onClick={() =>
                      setSiteType(type)}
                    className={`p-2 rounded-md border text-center text-sm transition-colors ${
                      siteType === type
                        ? "border-blue-500 bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300"
                        : "border-border hover:border-muted-foreground/50"
                    }`}
                  >
                    <div className="font-medium">{labels[type]}</div>
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {hints[type]}
                    </div>
                  </button>
                );
              },
            )}
          </div>

          {/* 企业版额外字段 */}
          {siteType === "enterprise" && (
            <div className="space-y-2 p-3 rounded-md border bg-muted/30">
              <div>
                <Label className="text-xs">
                  {t(
                    "codebuddyOauth.apiEndpoint",
                    "API 端点",
                  )}
                </Label>
                <Input
                  placeholder="https://your-enterprise.copilot.example.com"
                  value={apiEndpoint}
                  onChange={(e) => setApiEndpoint(e.target.value)}
                  className="h-8 text-sm mt-1"
                />
              </div>
              <div>
                <Label className="text-xs">
                  {t("codebuddyOauth.enterpriseId", "企业标识")}
                </Label>
                <Input
                  placeholder={t(
                    "codebuddyOauth.enterpriseIdPlaceholder",
                    "如: your-company",
                  )}
                  value={enterpriseId}
                  onChange={(e) => setEnterpriseId(e.target.value)}
                  className="h-8 text-sm mt-1"
                />
              </div>
              <div>
                <Label className="text-xs">
                  {t(
                    "codebuddyOauth.userAgent",
                    "User-Agent (可选)",
                  )}
                </Label>
                <Input
                  placeholder="CodeBuddyIDE/4.2.22590715"
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  className="h-8 text-sm mt-1"
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* 未认证 - 登录按钮 */}
      {!hasAnyAccount && pollingState === "idle" && (
        <Button
          type="button"
          onClick={handleAddAccount}
          className="w-full"
          variant="outline"
          disabled={
            siteType === "enterprise" &&
            (!apiEndpoint.trim() || !enterpriseId.trim())
          }
        >
          <Sparkles className="mr-2 h-4 w-4" />
          {t("codebuddyOauth.loginWithCodeBuddy", "选择站点并登录 CodeBuddy")}
        </Button>
      )}

      {/* 已有账号 - 添加更多按钮 */}
      {hasAnyAccount && pollingState === "idle" && (
        <Button
          type="button"
          onClick={handleAddAccount}
          className="w-full"
          variant="outline"
          disabled={
            isAddingAccount ||
            (siteType === "enterprise" &&
              (!apiEndpoint.trim() || !enterpriseId.trim()))
          }
        >
          <Plus className="mr-2 h-4 w-4" />
          {t("codebuddyOauth.addAnotherAccount", "添加其他 CodeBuddy 账号")}
        </Button>
      )}

      {/* 轮询中状态 */}
      {isPolling && deviceCode && (
        <div className="space-y-3 p-4 rounded-lg border border-border bg-muted/50">
          <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t("codebuddyOauth.waitingForAuth", "等待认证完成...")}
          </div>

          <div className="text-center">
            <p className="text-xs text-muted-foreground mb-1">
              {t(
                "codebuddyOauth.openLinkHint",
                "请在浏览器中选择站点并完成 CodeBuddy 登录：",
              )}
            </p>
            <a
              href={deviceCode.verification_uri}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm text-blue-500 hover:underline"
            >
              {t("codebuddyOauth.reopenConfigPage", "重新打开配置页面")}
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>

          <div className="text-center">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={cancelAuth}
            >
              {t("common.cancel", "取消")}
            </Button>
          </div>
        </div>
      )}

      {/* 错误状态 */}
      {pollingState === "error" && error && (
        <div className="space-y-2">
          <p className="text-sm text-red-500">{error}</p>
          <div className="flex gap-2">
            <Button
              type="button"
              onClick={handleAddAccount}
              variant="outline"
              size="sm"
            >
              {t("codebuddyOauth.retry", "重试")}
            </Button>
            <Button
              type="button"
              onClick={cancelAuth}
              variant="ghost"
              size="sm"
            >
              {t("common.cancel", "取消")}
            </Button>
          </div>
        </div>
      )}

      {/* 注销所有账号 */}
      {hasAnyAccount && accounts.length > 1 && (
        <Button
          type="button"
          variant="outline"
          onClick={logout}
          className="w-full text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950"
        >
          <LogOut className="mr-2 h-4 w-4" />
          {t("codebuddyOauth.logoutAll", "注销所有账号")}
        </Button>
      )}
    </div>
  );
};

export default CodeBuddyOAuthSection;
