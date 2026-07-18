# dist/

The runnable bundle (`cdn-detect-pack.js`) is not built yet. The plugins currently ship as
**built-in** reference plugins inside the Vineyard app (manifest members use `entry: "inline"`).
This catalog manifest exists so the pack is listable/installable in the marketplace; remote
execution from this repo lands when the bundle is built and committed here.
