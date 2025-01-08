import react from "@vitejs/plugin-react";
import * as path from "path";
import postcssNesting from "postcss-nesting";
import { defineConfig } from "vite";
import checker from "vite-plugin-checker";
import { viteSingleFile } from "vite-plugin-singlefile";

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
const isDev = process.env.NODE_ENV === "development";

console.log(
  path.resolve(
    root,
    "./node_modules/@bufbuild/protobuf/dist/esm/wkt/index.d.ts"
  )
);

export default defineConfig(() => ({
  root: src,
  base: "",
  build: {
    // outDir: path.resolve(root, "isovalent_platform2/appserver/static"),
    outDir: path.resolve(root, "..", "cmd", "tetra", "exec", "ui"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        app: isDev
          ? path.resolve(src, "index.html")
          : path.resolve(src, "index.html"),
      },
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
    checker({
      typescript: { tsconfigPath: path.resolve(root, "tsconfig.json") },
    }),
    viteSingleFile(),
  ],
}));
