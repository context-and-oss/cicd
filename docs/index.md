# Documentation

The repository is currently private. Remote module, action and reusable-workflow
examples are conditional on authorized access, not a promise of public availability.
See [availability and source access](../README.md#availability-and-source-access)
for separate read-only source-checkout/local-module use. Anonymous fetching applies
only after authorized publication and verification of the referenced release.

## Getting started

If you are deciding whether this belongs in your delivery flow, start with
[Getting started](./tutorials/getting-started.md). It answers the practical first
questions: why use these modules, how to run everything, how to run only one
piece, how to build your own pipeline, and how to combine modules without taking
the whole stack.

For direct setup work:

| Goal | Guide |
|------|-------|
| Run the complete pre-commit and commit pipelines | [Use the complete pipeline](./how-to-guides/use-complete-pipeline.md) |
| Adopt only selected checks | [Use individual modules](./how-to-guides/use-individual-modules.md) |
| Build your own Dagger pipeline around these modules | [Build your own pipeline](./how-to-guides/build-your-own-pipeline.md) |
| Combine modules for different teams, stages, or risk levels | [Mix and match modules](./how-to-guides/mix-and-match-modules.md) |
| Ship a zip/folder instead of a container (Dataverse, Azure Web App) | [Use the pipeline without a Dockerfile](./how-to-guides/use-without-dockerfile.md) |

## Four Ways to Use This Documentation

The documentation is organized using the [Diataxis](https://diataxis.fr/) framework. Each quadrant serves a different need:

| Section                                   | Purpose                              | Start here when...                                     |
|-------------------------------------------|--------------------------------------|--------------------------------------------------------|
| [Tutorials](./tutorials/index.md)         | Learning-oriented lessons            | You are new to cicd and want to learn by doing          |
| [How-to Guides](./how-to-guides/index.md) | Task-oriented recipes                | You need to accomplish a specific goal                 |
| [Reference](./reference/index.md)         | Information-oriented technical facts | You need accurate, complete technical details          |
| [Explanation](./explanation/index.md)     | Understanding-oriented discussion    | You want to understand why things work the way they do |

The [engineering doctrine](./explanation/doctrine.md) is the one page to read
before changing a scanner, linter or gate, and the [glossary](./explanation/glossary.md)
defines the words the rest of the documentation uses with a fixed meaning.

Every diagram under `docs/assets/` is a `.drawio.png`: the PNG carries its own
draw.io source, so open the file in [draw.io](https://www.drawio.com/) to edit
it and export it back over itself with the diagram embedded. A re-export that
drops the source leaves an image nobody can change.
