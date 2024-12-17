# Application Model UI: much apps, such visualization

Run:

    ./tetra pstree show -o web

to connect to the local Tetragon instance and visualize the application model.

You can also pipe the application model JSON from stdin. For example, to visualize
the latest application model from the squash pod:

    kubectl logs -n tetragon deployment/squash | tail -n 1 | ./tetra pstree show -o web
