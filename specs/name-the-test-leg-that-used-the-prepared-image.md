# Name the test leg that used the prepared image

## Why

The first v4.4.0 consumer pilots proved that a selected .NET test leg branches
from the prepared container, but their evidence still warned that no test leg
ran in the run-wide toolchain image. That sentence predates prepared legs and
was emitted unconditionally whenever a caller combined `test-legs` with
`toolchain-image`.

We chose to retain the scope warning because consumers still need to know that
other declared legs resolve their own images. When preparation selects a leg,
the warning now says that the run-wide image supplied that named prepared leg
and limits the per-leg resolution statement to every other leg.

## What changed

The test-leg scope warning accepts the prepared label. With no prepared label it
keeps the existing ignored-image wording. With a prepared label it names the
leg that inherited the prepared container and no longer claims the image was
unused.

A focused regression test covers both messages and refuses the contradictory
phrases in the prepared case.
