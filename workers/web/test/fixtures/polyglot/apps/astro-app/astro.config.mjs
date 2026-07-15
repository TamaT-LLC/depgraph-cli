import { writeFileSync } from "node:fs";
writeFileSync(new URL("./ASTRO_CONFIG_EXECUTED", import.meta.url), "unsafe");
export default {
  base: "/docs",
  srcDir: "./src",
  integrations: [process.env.NEVER_EXECUTE_PROJECT_CONFIG]
};
