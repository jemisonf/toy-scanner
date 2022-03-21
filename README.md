# Toy Container Vulnerability Scanner

This is a small tool that can (theoretically) scan an Alpine container image and detect any vulnerable APK packages that have been reported to Alpine SecDB. You can run with:

```
go run . -image alpine
```

Where the `-image` flag accepts most formats for image identifiers.

The code is based on a simpler version of the architecture for [Clare](https://quay.github.io/claircore/what_is.html), and borrows particularly strongly from Clare's [Alpine indexer](https://github.com/quay/claircore/tree/main/alpine). Many thanks to the Clare developers for the easy-to-read code and documentation, without which this probably would not have been possible.

It hopefully goes without saying, but under absolutely no circumstances should this code be used in production.

For a detailed write up of this project, check out ["Building a Toy Container Vulnerability Scanner"](https://fgj.codes/posts/building-a-toy-vulnerability-scanner/).
