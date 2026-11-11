/// <reference types="vite/client" />

import type { TanweiApi } from "../../preload";

declare global {
  interface Window {
    tanwei: TanweiApi;
  }
}

export {};
