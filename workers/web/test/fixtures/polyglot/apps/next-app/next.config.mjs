import { writeFileSync } from "node:fs";
writeFileSync(new URL("./NEXT_CONFIG_EXECUTED", import.meta.url), "unsafe");
export default {
  basePath: "/shop",
  pageExtensions: ["tsx", "ts"],
  webpack: process.env.NEVER_EXECUTE_PROJECT_CONFIG
};
