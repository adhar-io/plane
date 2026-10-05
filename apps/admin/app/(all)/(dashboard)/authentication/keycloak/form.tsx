/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { isEmpty } from "lodash-es";
import Link from "next/link";
import { useForm } from "react-hook-form";
// plane internal packages
import { API_BASE_URL } from "@plane/constants";
import { Button } from "@makeplane/propel/components/button";
import { setToast } from "@plane/blocks/toast";
import type { IFormattedInstanceConfiguration, TInstanceKeycloakAuthenticationConfigurationKeys } from "@plane/types";
// components
import { CodeBlock } from "@/components/common/code-block";
import { ConfirmDiscardModal } from "@/components/common/confirm-discard-modal";
import type { TControllerInputFormField } from "@/components/common/controller-input";
import { ControllerInput } from "@/components/common/controller-input";
import type { TControllerSwitchFormField } from "@/components/common/controller-switch";
import { ControllerSwitch } from "@/components/common/controller-switch";
import type { TCopyField } from "@/components/common/copy-field";
import { CopyField } from "@/components/common/copy-field";
// hooks
import { useInstance } from "@/hooks/store";

type Props = {
  config: IFormattedInstanceConfiguration;
};

type KeycloakConfigFormValues = Record<TInstanceKeycloakAuthenticationConfigurationKeys, string>;

const KEYCLOAK_FORM_SWITCH_FIELD: TControllerSwitchFormField<KeycloakConfigFormValues> = {
  name: "ENABLE_KEYCLOAK_SYNC",
  label: "Keycloak",
};

export function InstanceKeycloakConfigForm(props: Props) {
  const { config } = props;
  // states
  const [isDiscardChangesModalOpen, setIsDiscardChangesModalOpen] = useState(false);
  // store hooks
  const { updateInstanceConfigurations } = useInstance();
  // form data
  const {
    handleSubmit,
    control,
    reset,
    formState: { errors, isDirty, isSubmitting },
  } = useForm<KeycloakConfigFormValues>({
    defaultValues: {
      KEYCLOAK_ISSUER_URL: config["KEYCLOAK_ISSUER_URL"] || "",
      KEYCLOAK_INTERNAL_ISSUER_URL: config["KEYCLOAK_INTERNAL_ISSUER_URL"] || "",
      KEYCLOAK_CLIENT_ID: config["KEYCLOAK_CLIENT_ID"],
      KEYCLOAK_CLIENT_SECRET: config["KEYCLOAK_CLIENT_SECRET"],
      ENABLE_KEYCLOAK_SYNC: config["ENABLE_KEYCLOAK_SYNC"] || "0",
    },
  });

  const originURL = !isEmpty(API_BASE_URL) ? API_BASE_URL : typeof window !== "undefined" ? window.location.origin : "";

  const KEYCLOAK_FORM_FIELDS: TControllerInputFormField<KeycloakConfigFormValues>[] = [
    {
      key: "KEYCLOAK_ISSUER_URL",
      type: "text",
      label: "Realm issuer URL",
      description: (
        <>
          The realm&apos;s issuer, not the server root — Plane reads the endpoints from{" "}
          <CodeBlock darkerShade>&lt;issuer&gt;/.well-known/openid-configuration</CodeBlock>, so this works on any
          Keycloak version (the realm path moved from <CodeBlock darkerShade>/auth/realms</CodeBlock> to{" "}
          <CodeBlock darkerShade>/realms</CodeBlock> in Keycloak 17).
        </>
      ),
      placeholder: "https://keycloak.example.com/realms/adhar",
      error: Boolean(errors.KEYCLOAK_ISSUER_URL),
      required: true,
    },
    {
      key: "KEYCLOAK_INTERNAL_ISSUER_URL",
      type: "text",
      label: "Internal issuer URL (optional)",
      description: (
        <>
          Set this when the API server reaches Keycloak over a private network, such as a cluster-local service URL.
          Plane fetches discovery and exchanges tokens there, while browsers are still sent to the realm issuer above
          for the login page.
        </>
      ),
      placeholder: "http://keycloak.keycloak.svc.cluster.local:8080/keycloak/realms/adhar",
      error: Boolean(errors.KEYCLOAK_INTERNAL_ISSUER_URL),
      required: false,
    },
    {
      key: "KEYCLOAK_CLIENT_ID",
      type: "text",
      label: "Client ID",
      description: (
        <>
          The <CodeBlock darkerShade>Client ID</CodeBlock> of the OpenID Connect client in your realm.
        </>
      ),
      placeholder: "plane",
      error: Boolean(errors.KEYCLOAK_CLIENT_ID),
      required: true,
    },
    {
      key: "KEYCLOAK_CLIENT_SECRET",
      type: "password",
      label: "Client secret",
      description: (
        <>
          From <CodeBlock darkerShade>Clients &rarr; Credentials</CodeBlock> in the realm. The client must be
          confidential (<CodeBlock darkerShade>Client authentication</CodeBlock> on).
        </>
      ),
      placeholder: "••••••••••••••••••••••••••••••••",
      error: Boolean(errors.KEYCLOAK_CLIENT_SECRET),
      required: true,
    },
  ];

  const KEYCLOAK_SERVICE_FIELD: TCopyField[] = [
    {
      key: "Callback_URI",
      label: "Callback URI",
      url: `${originURL}/auth/keycloak/callback/`,
      description: (
        <>
          We will auto-generate this. Add it to the client&apos;s <CodeBlock darkerShade>Valid redirect URIs</CodeBlock>{" "}
          in the realm — Keycloak refuses the login with <CodeBlock darkerShade>invalid_redirect_uri</CodeBlock> when it
          is missing.
        </>
      ),
    },
  ];

  const onSubmit = async (formData: KeycloakConfigFormValues) => {
    const payload: Partial<KeycloakConfigFormValues> = { ...formData };

    try {
      const response = await updateInstanceConfigurations(payload);
      setToast({
        type: "success",
        title: "Done!",
        message: "Your Keycloak authentication is configured. You should test it now.",
      });
      reset({
        KEYCLOAK_ISSUER_URL: response.find((item) => item.key === "KEYCLOAK_ISSUER_URL")?.value,
        KEYCLOAK_INTERNAL_ISSUER_URL: response.find((item) => item.key === "KEYCLOAK_INTERNAL_ISSUER_URL")?.value,
        KEYCLOAK_CLIENT_ID: response.find((item) => item.key === "KEYCLOAK_CLIENT_ID")?.value,
        KEYCLOAK_CLIENT_SECRET: response.find((item) => item.key === "KEYCLOAK_CLIENT_SECRET")?.value,
        ENABLE_KEYCLOAK_SYNC: response.find((item) => item.key === "ENABLE_KEYCLOAK_SYNC")?.value,
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleGoBack = (e: React.MouseEvent<HTMLAnchorElement, MouseEvent>) => {
    if (isDirty) {
      e.preventDefault();
      setIsDiscardChangesModalOpen(true);
    }
  };

  return (
    <>
      <ConfirmDiscardModal
        isOpen={isDiscardChangesModalOpen}
        onDiscardHref="/authentication"
        handleClose={() => setIsDiscardChangesModalOpen(false)}
      />
      <div className="flex flex-col gap-8">
        <div className="grid w-full grid-cols-2 gap-x-12 gap-y-8">
          <div className="col-span-2 flex flex-col gap-y-4 pt-1 md:col-span-1">
            <div className="pt-2.5 text-18 font-medium">Keycloak-provided details for Plane</div>
            {KEYCLOAK_FORM_FIELDS.map((field) => (
              <ControllerInput
                key={field.key}
                control={control}
                type={field.type}
                name={field.key}
                label={field.label}
                description={field.description}
                placeholder={field.placeholder}
                error={field.error}
                required={field.required}
              />
            ))}
            <ControllerSwitch control={control} field={KEYCLOAK_FORM_SWITCH_FIELD} />
            <div className="flex flex-col gap-1 pt-4">
              <div className="flex items-center gap-4">
                <Button
                  variant="primary"
                  size="md"
                  stretch="auto"
                  onClick={(e) => void handleSubmit(onSubmit)(e)}
                  loading={isSubmitting}
                  disabled={!isDirty}
                  label={isSubmitting ? "Saving" : "Save changes"}
                />
                <Button
                  variant="secondary"
                  size="md"
                  stretch="auto"
                  nativeButton={false}
                  render={<Link href="/authentication" onClick={handleGoBack} />}
                  label="Go back"
                />
              </div>
            </div>
          </div>
          <div className="col-span-2 md:col-span-1">
            <div className="flex flex-col gap-y-4 rounded-lg bg-layer-1 px-6 pt-1.5 pb-4">
              <div className="pt-2 text-18 font-medium">Plane-provided details for Keycloak</div>
              {KEYCLOAK_SERVICE_FIELD.map((field) => (
                <CopyField key={field.key} label={field.label} url={field.url} description={field.description} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
