// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The security-advisory surface (issue #163): the banner projection and the
// offline bundle import.
//
// The banner list renders ONLY accepted advisories: every row was verified by
// the server before it was stored (the feed's single verification path), so
// this surface never renders an unverified advisory. The import form takes the
// SAME signed bundle the online poll consumes - the server rejects a bundle
// whose signature does not verify ENTIRELY, so a tampered bundle cannot inject
// one advisory while the rest fails.
//
// Advisories live UNDER an environment, so this surface reads BOTH the active
// tenant and environment from the scope store and injects them into every
// call, exactly as the diagnostics and connectors surfaces do. When no
// {tenant, environment} is in scope it shows a prompt and makes ZERO calls.
// It reads ONLY through the named wrappers in src/api/client.ts (the single
// funnel) and renders every failure through the verbatim ErrorView boundary.
//
// Every rendered field is operator-visible and NON secret (the advisory id,
// title, summary, and severity are the feed author's public text): they are
// rendered as TEXT children, which Preact escapes by construction, so a
// hostile-looking summary renders INERT. This view uses NO
// dangerouslySetInnerHTML.

import { useState } from "preact/hooks";
import {
  type AdvisoryView,
  fetchSecurityAdvisories,
  importSecurityAdvisories,
} from "../api/client";
import { activeScope } from "../scope/store";
import { AsyncBoundary, MutationFeedback, ResourceHeading } from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

// The severity tier drives the banner's emphasis; an unknown tier renders as
// "low" (inert text, never a crash).
function severityLabel(severity: string): string {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    default:
      return "low";
  }
}

// A single advisory banner.
function AdvisoryBanner({ advisory }: { advisory: AdvisoryView }) {
  const tier = severityLabel(advisory.severity);
  return (
    <div className={`advisory-banner advisory-banner--${tier}`}>
      <div className="advisory-banner__head">
        <span className="advisory-banner__id">{advisory.id}</span>
        <span className="advisory-banner__severity">{tier}</span>
      </div>
      <div className="advisory-banner__title">{advisory.title}</div>
      <div className="advisory-banner__summary">{advisory.summary}</div>
      {advisory.affected_versions.length > 0 && (
        <div className="advisory-banner__versions">
          affected: {advisory.affected_versions.join(", ")}
        </div>
      )}
    </div>
  );
}

// The offline bundle import form: paste the signed feed document (the `feed`
// member plus the `signature` member) and import it. The server runs the SAME
// verification the online poll runs; a failed verification is a 400.
function ImportForm() {
  const [feed, setFeed] = useState("");
  const scope = activeScope.value;

  const mutation = useMutation();
  const canImport = scope !== null && scope.environmentId !== undefined;

  if (!canImport) {
    return null;
  }

  return (
    <div className="advisory-import">
      <h2>Import the signed advisory bundle</h2>
      <p>
        The same bundle the online poll consumes, for air-gapped deployments.
        The signature is verified before anything is stored; a bundle that
        fails verification is rejected entirely.
      </p>
      <textarea
        value={feed}
        onChange={(event) => setFeed(event.currentTarget.value)}
        placeholder='{"feed": [...], "signature": "..."}'
        rows={6}
      />
      <button
        type="button"
        disabled={feed.trim() === "" || mutation.state.pending}
        onClick={() =>
          void mutation.run(
            async () => {
              if (scope === null || scope.environmentId === undefined) {
                return;
              }
              await importSecurityAdvisories(scope.tenantId, scope.environmentId, feed);
            },
            "The verified advisories replaced the accepted set",
          )
        }
      >
        Import and verify
      </button>
      <MutationFeedback state={mutation.state} />
    </div>
  );
}

// The advisory surface: the banner list plus the offline import form.
export function AdvisoriesView() {
  const scope = activeScope.value;
  const advisories = useAsyncResource(
    async () => {
      if (scope === null || scope.environmentId === undefined) {
        return { advisories: [] };
      }
      return fetchSecurityAdvisories(scope.tenantId, scope.environmentId);
    },
    [scope?.tenantId, scope?.environmentId],
  );

  if (scope === null || scope.environmentId === undefined) {
    return (
      <ResourceHeading
        id="advisories"
        title="Security advisories"
        description="Select a tenant and environment to read its security advisories."
      />
    );
  }

  return (
    <>
      <ResourceHeading
        id="advisories"
        title="Security advisories"
        description="The accepted security advisories for this environment, plus the offline bundle import."
      />
      <div>
        <AsyncBoundary state={advisories.state}>
        {(list) =>
          list.advisories.length === 0 ? (
            <p>
              No accepted advisories. A deployment with no published advisory
              renders nothing; the feed is never load-bearing.
            </p>
          ) : (
            <div className="advisory-list">
              {list.advisories.map((advisory) => (
                <AdvisoryBanner key={advisory.id} advisory={advisory} />
              ))}
            </div>
          )
        }
        </AsyncBoundary>
        <ImportForm />
      </div>
    </>
  );
}