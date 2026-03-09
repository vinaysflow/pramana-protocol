/**
 * Shared test wrapper: wraps a component in <PramanaProvider>.
 */
import React, { type ReactNode } from "react";
import { PramanaProvider } from "../src/context.js";

export function makeWrapper(
  props: { apiUrl?: string; authToken?: string } = {},
) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <PramanaProvider apiUrl={props.apiUrl} authToken={props.authToken}>
        {children}
      </PramanaProvider>
    );
  };
}
