import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves this project from /ThreatWeave/.
// Render/local deployments can override this with VITE_BASE_PATH=/.
export default defineConfig({
  base: process.env.VITE_BASE_PATH || "/ThreatWeave/",
  plugins: [react()],
});
