# Docker Guide

This repository has a `Dockerfile` in the root which builds an image with the
`lighthouse` binary installed.

To use the image, first build it (this will likely take several minutes):

```bash
$ docker build . -t lighthouse
```

Once it's built, run it with:

```bash
$ docker run lighthouse lighthouse --help
```

_Note: the first `lighthouse` is the name of the tag we created earlier. The
second `lighthouse` refers to the binary installed in the image._
