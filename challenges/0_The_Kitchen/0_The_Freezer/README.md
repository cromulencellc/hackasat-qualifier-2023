# Quals Challenge: Basic File #

This is a basic "sanity check" service for players. All they have to do is
download the generated file, untar it, and put the flag in the scoreboard.
For people that have never seen a CTF before, this should be a good example
of how flag submission works. It's also a good way to test our generator
infrastructure.


## Building ##

This repository contains two Docker images: The `generator` and the `solver`.
You can build both with:

```sh
make build
```

The resulting Docker images will be tagged as `basic-file:generator` and
`basic-file:solver`.

You can also build just one of them with `make generator` or `make solver`
respectively.

