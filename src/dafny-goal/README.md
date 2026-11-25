# Extracted goal kernel (generated, do not edit)

This directory holds the Java translation of the Dafny-proved goal compiler (`formal/dafny/Goal.dfy` in the flagship repository)
and the Dafny Java runtime, produced with the pinned Dafny (`formal/dafny/TOOLCHAIN.lock`) by `formal/dafny/build-native.sh java`.
The files keep Dafny's package names (`GoalApi`, `GoalIr`, ..., `dafny`) and compile with the rest of `src/`.
CI produces it: the "Goal kernel native extractions" workflow translates the same sources, fails when the files committed here
differ from a fresh translation, and uploads the fresh translation as an artifact to commit.

`net.atlasauth.pca.goal.GoalKernel` loads it by class name at first use, so the SDK builds while this directory holds only the
README; until then every kernel call throws `GoalKernelUnavailable` (there is no fallback) and `GoalKernelTest` skips its kernel
tests (set `PCA_GOAL_KERNEL_REQUIRE=1` to make them fail). Only this README is written by hand; `build-native.sh` keeps it and
replaces every other file.
