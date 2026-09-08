import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // GitHub Pages serves project sites below the repository name.
  base: "/ForenSight/",
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
  },
});
