export default {
  // basepath: "/commented-example-must-not-apply",
  basepath: "/router",
  routesDirectory: "./src/routes",
  generatedRouteTree: "./src/routeTree.gen.ts",
  virtualRouteConfig: {
    type: "root",
    children: [
      { type: "route", path: "virtual", file: "./src/virtual.tsx" }
    ]
  },
  plugins: [process.env.NEVER_EXECUTE_PROJECT_CONFIG]
};
