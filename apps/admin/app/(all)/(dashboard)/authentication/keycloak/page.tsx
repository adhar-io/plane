/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { observer } from "mobx-react";
import useSWR from "swr";
// plane internal packages
import { Switch } from "@makeplane/propel/components/switch";
// assets
import keycloakLogo from "@/app/assets/logos/keycloak-logo.svg?url";
// components
import { AuthenticationMethodCard } from "@/components/authentication/authentication-method-card";
import { PageWrapper } from "@/components/common/page-wrapper";
import { Skeleton } from "@/components/common/skeleton";
import { setPromiseToast } from "@plane/blocks/toast";
// hooks
import { useInstance } from "@/hooks/store";
// types
import type { Route } from "./+types/page";
// local
import { InstanceKeycloakConfigForm } from "./form";

const InstanceKeycloakAuthenticationPage = observer(function InstanceKeycloakAuthenticationPage() {
  // store
  const { fetchInstanceConfigurations, formattedConfig, updateInstanceConfigurations } = useInstance();
  // state
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  // config
  const enableKeycloakConfig = formattedConfig?.IS_KEYCLOAK_ENABLED ?? "";
  useSWR("INSTANCE_CONFIGURATIONS", () => fetchInstanceConfigurations());

  const updateConfig = async (key: "IS_KEYCLOAK_ENABLED", value: string) => {
    setIsSubmitting(true);

    const payload = {
      [key]: value,
    };

    const updateConfigPromise = updateInstanceConfigurations(payload);

    setPromiseToast(updateConfigPromise, {
      loading: "Saving Configuration",
      success: {
        title: "Configuration saved",
        message: () => `Keycloak authentication is now ${value === "1" ? "active" : "disabled"}.`,
      },
      error: {
        title: "Error",
        message: () => "Failed to save configuration",
      },
    });

    try {
      await updateConfigPromise;
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const isKeycloakEnabled = enableKeycloakConfig === "1";

  return (
    <PageWrapper
      customHeader={
        <AuthenticationMethodCard
          name="Keycloak"
          description="Allow members to sign in with their Keycloak account — any OpenID Connect realm."
          icon={<img src={keycloakLogo} height={24} width={24} alt="Keycloak Logo" />}
          config={
            <Switch
              aria-label="Enable Keycloak authentication"
              checked={isKeycloakEnabled}
              onCheckedChange={() => {
                updateConfig("IS_KEYCLOAK_ENABLED", isKeycloakEnabled ? "0" : "1");
              }}
              size="sm"
              disabled={isSubmitting || !formattedConfig}
            />
          }
          disabled={isSubmitting || !formattedConfig}
          withBorder={false}
        />
      }
    >
      {formattedConfig ? (
        <InstanceKeycloakConfigForm config={formattedConfig} />
      ) : (
        <Skeleton className="space-y-8">
          <Skeleton.Item height="50px" width="25%" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" width="50%" />
        </Skeleton>
      )}
    </PageWrapper>
  );
});
export const meta: Route.MetaFunction = () => [{ title: "Keycloak Authentication - God Mode" }];

export default InstanceKeycloakAuthenticationPage;
