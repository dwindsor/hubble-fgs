import react from "@vitejs/plugin-react";
import * as path from "path";
import postcssNesting from "postcss-nesting";
import { defineConfig, LibraryFormats } from "vite";
import checker from "vite-plugin-checker";
import { viteSingleFile } from "vite-plugin-singlefile";
import { libInjectCss } from "vite-plugin-lib-inject-css";

const root = __dirname;
const src = path.resolve(root, "src");
const ipa = path.resolve(
  root,
  "..",
  "vendor",
  "github.com",
  "isovalent",
  "ipa"
);
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
              entry: path.resolve(src, "components", "Root.tsx"),
              name: "IsovalentProcessAncestry",
              fileName: "process-ancestry",
              formats: ["umd"] as LibraryFormats[],
            },
          }),
      outDir:
        appType === "app"
          ? path.resolve(root, "..", "cmd", "tetra", "exec", "ui")
          : path.resolve(root, "lib"),
      emptyOutDir: true,
      rollupOptions: {
        input: {
          app:
            appType === "app"
              ? path.resolve(src, "index.html")
              : path.resolve(src, "components", "Root.tsx"),
        },
        external:
          appType === "app"
            ? []
            : ["react", "react-dom", "react-dom/client", "react/jsx-runtime"],
      },
    },
    resolve: {
      alias: {
        "~": src,
        "@ipa": ipa,
        "@bufbuild/protobuf": path.resolve(
          root,
          "./node_modules/@bufbuild/protobuf/dist/esm"
        ),
        "@bufbuild/protobuf/wkt": path.resolve(
          root,
          "./node_modules/@bufbuild/protobuf/dist/esm/wkt"
        ),
        "@bufbuild/protobuf/codegenv1": path.resolve(
          root,
          "./node_modules/@bufbuild/protobuf/dist/esm/codegenv1"
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
      checker({
        typescript: { tsconfigPath: path.resolve(root, "tsconfig.json") },
      }),
      appType === "app" && viteSingleFile(),
    ],
  };
});
