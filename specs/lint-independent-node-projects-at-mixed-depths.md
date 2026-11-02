# Lint independent Node projects at mixed depths

`src/quality/nodeproject.go` used one global minimum depth when selecting Node
projects. That omitted any independent application whose package manifest sat
deeper than an unrelated sibling, even though language detection had found it.
The resulting commit evidence could therefore report a clean repository after
never installing, linting, or testing that application.

The four-application fixture demonstrates the failure: three applications keep
their package manifests one directory below the repository root, while a fourth
application keeps its manifest below an additional `apps` directory. Since none
of those project directories is an ancestor of another, all four are independent
and all four must run.

We changed the selection rule to retain every discovered project directory that
has no package-bearing ancestor. This preserves root workspace behavior because
a root package still governs every nested package, and it preserves nested
workspace behavior for the same reason. It also removes depth as a relationship
between unrelated directory trees. `src/quality/nodeproject_test.go` fixes the
four-application layout in a regression case so a future resolver cannot omit
the deeper project silently.

The existing four-project ceiling remains in force because each independent
project starts its own dependency installation and tool run. A fifth project is
still an explicit non-run with the complete project list instead of a partial
green result.
