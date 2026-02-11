import * as path from "node:path";
import react from "@vitejs/plugin-react";
import postcssNesting from "postcss-nesting";
import { type LibraryFormats, defineConfig } from "vite";
import checker from "vite-plugin-checker";
import dts from "vite-plugin-dts";
import { libInjectCss } from "vite-plugin-lib-inject-css";
import { viteSingleFile } from "vite-plugin-singlefile";

const root = __dirname;
const src = path.resolve(root, "src");
const ipa = path.resolve(root, "..", "vendor", "github.com", "isovalent", "ipa");
const appType = process.env.APP_TYPE ?? "app";

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
      libInjectCss(),
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
