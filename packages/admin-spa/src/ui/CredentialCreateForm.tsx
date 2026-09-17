// SPDX-License-Identifier: MIT OR Apache-2.0

import { useEffect, useState } from "preact/hooks";
import { MutationFeedback, ResourceFormIntro } from "./ResourceView";
import { inputValue, sudoFor } from "./orgPanels";
import type { Mutation } from "./useResource";

// The draft belongs to the dialog; the one-time credential belongs to its panel.
export function CredentialCreateForm({
  title,
  nameLabel,
  submitLabel,
  successMessage,
  mutation,
  onCreate,
  onCreated,
}: {
  title: string;
  nameLabel: string;
  submitLabel: string;
  successMessage: string;
  mutation: Mutation;
  onCreate: (name: string) => Promise<void>;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [submitted, setSubmitted] = useState(false);
  useEffect(() => {
    if (
      submitted &&
      !mutation.state.pending &&
      mutation.state.success !== null
    ) {
      onCreated();
    }
  }, [submitted, mutation.state.pending, mutation.state.success, onCreated]);
  return (
    <form
      class="resource-form"
      aria-label={title}
      onSubmit={(event) => {
        event.preventDefault();
        const trimmed = name.trim();
        if (trimmed === "") return;
        setSubmitted(true);
        void mutation.run(async () => {
          await onCreate(trimmed);
        }, successMessage);
      }}
    >
      <ResourceFormIntro
        title={title}
        headingLevel={3}
        description="Choose a name to identify this credential. Save it after creation; it is shown only once."
      />
      <label class="resource-field">
        {nameLabel}
        <input
          type="text"
          required
          placeholder="Production integration"
          value={name}
          disabled={mutation.state.pending}
          onInput={(event) => setName(inputValue(event))}
        />
      </label>
      <button
        class="resource-btn resource-btn-primary"
        type="submit"
        disabled={mutation.state.pending || name.trim() === ""}
      >
        {submitLabel}
      </button>
      <MutationFeedback
        state={
          submitted
            ? mutation.state
            : {
                pending: mutation.state.pending,
                error: null,
                success: null,
              }
        }
        sudo={sudoFor(mutation.retry)}
      />
    </form>
  );
}
