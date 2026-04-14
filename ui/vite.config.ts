import * as fs from "node:fs";
import * as path from "node:path";
import react from "@vitejs/plugin-react";
import postcssNesting from "postcss-nesting";
import { type LibraryFormats, defineConfig } from "vite";
import checker from "vite-plugin-checker";
import dts from "vite-plugin-dts";
import { libInjectCss } from "vite-plugin-lib-inject-css";
import { viteSingleFile } from "vite-plugin-singlefile";

const root = __dirname;
const repoRoot = path.resolve(root, "..");
const src = path.resolve(root, "src");
const ipa = path.resolve(repoRoot, "vendor", "github.com", "isovalent", "ipa");
const appType = process.env.APP_TYPE ?? "app";

// vite-plugin-dts uses @microsoft/api-extractor for rollupTypes, which requires
// a package.json reachable from rootDir. With rootDir: ".." (needed for vendor
// files outside ui/), it looks at the repo root. This plugin creates a temporary
// package.json there during the build so we don't have to commit one.
function tempRootPackageJson(): import("vite").Plugin {
  const pkgPath = path.resolve(repoRoot, "package.json");
  let created = false;
  return {
    name: "temp-root-package-json",
    buildStart() {
      if (!fs.existsSync(pkgPath)) {
        fs.writeFileSync(pkgPath, '{"name":"hubble-fgs","private":true}\n');
        created = true;
      }
    },
    closeBundle() {
      if (created) {
        fs.unlinkSync(pkgPath);
        created = false;
      }
    },
  };
}

export default defineConfig(() => {
  return {
    root: src,
    base: "",
    build: {
      ...(appType === "app"
        ? {}
        : {
            lib: {
              entry: path.resolve(src, "index.ts"),
              name: "IsovalentProcessAncestry",
              fileName: "process-ancestry",
              formats: ["es", "umd"] as LibraryFormats[],
            },
          }),
      outDir:
        appType === "app"
          ? path.resolve(root, "..", "cmd", "tetra", "exec", "ui")
          : path.resolve(root, "lib"),
      emptyOutDir: true,
      rollupOptions: {
        input: {
          app: appType === "app" ? path.resolve(src, "index.html") : path.resolve(src, "index.ts"),
        },
        external:
          appType === "app" ? [] : ["react", "react-dom", "react-dom/client", "react/jsx-runtime"],
        output: {
          globals: {
            react: "React",
            "react-dom": "ReactDOM",
            "react-dom/client": "ReactDOM",
            "react/jsx-runtime": "jsxRuntime",
          },
        },
      },
    },
    resolve: {
      alias: {
        "~": src,
        "@ipa": ipa,
        "@bufbuild/protobuf": path.resolve(root, "./node_modules/@bufbuild/protobuf/dist/esm"),
        "@bufbuild/protobuf/wkt": path.resolve(
          root,
          "./node_modules/@bufbuild/protobuf/dist/esm/wkt",
        ),
        "@bufbuild/protobuf/codegenv2": path.resolve(
          root,
          "./node_modules/@bufbuild/protobuf/dist/esm/codegenv2",
        ),
      },
    },
    css: {
      postcss: {
        plugins: [postcssNesting],
      },
    },
    plugins: [
      react(),
      appType === "lib" && libInjectCss(),
      appType === "lib" && tempRootPackageJson(),
      appType === "lib" &&
        dts({
          root: root,
          tsconfigPath: path.resolve(root, "tsconfig.lib.json"),
          entryRoot: src,
          rollupTypes: true,
        }),
      checker({
        typescript: { tsconfigPath: path.resolve(root, "tsconfig.json") },
      }),
      appType === "app" && viteSingleFile(),
    ],
  };
});
