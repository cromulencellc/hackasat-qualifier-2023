# Quals Challenge: As Below

**Category:** The Magician
**Relative Difficulty:** 2/5
**Author:** [Cromulence](https://cromulence.com/)

A whole pile of wasm crackmes,
designed to functionally require program analysis to
solve them.

## Dev Work and Generating Binaries

This challenge ships with a `Dockerfile-dev` used to enable quickly cycling on
C++ dev, including `gdb`.

**DO NOT USE THIS IMAGE TO RUN THE CHALLENGE IN A PUBLICLY VISIBLE WAY.**
The `docker run` command it calls
removes seccomp protections and
adds the `SYS_PTRACE` capability and
that's probably not what you want other people connecting to and hacking lol.

```sh
make dev
```

## IMPORTANT: Production / Integration
- `builder` generates the challenge binaries provided to teams as static files. Its Dockerfile is under `./challenge`
- `runner` is the challenge we host on infrastructure that the teams interact with. It requires the binaries from `builder` to be built. It's Dockerfile is under `./runner`
This challenge generates new static files every time CI is run that are mated to the newly built `runner` image. This `runner` image is retagged as `challenge` to work with the production infrastructure which expects this tag. If CI runs and that new image is pushed to production, make sure to update the set of static files being provided to the teams (these will be an artifact of the latest CI build).

The teams should only be provided the `as-below.tar` artifict, NOT `hints.json`. The `hints.json` is used by the solver.