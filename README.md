# Shared image security admission distribution

Generated from the exact source recorded in `_source.json`. This distribution
is not a second editable policy. Changes belong in the canonical private
`sichimi/sichimi-ci` repository and must be reviewed, then redistributed.
Consumers pin an exact reviewed distribution commit and declare image inputs;
they do not fork code, minimum versions or evidence freshness rules.

This action reads caller source using Python. It performs no image build,
Registry write, deployment, credential change or external network request.
Its approved-allowlist check is not itself a scanner or signature verifier.
A successful format check is not evidence that submitted summaries are true.

The distribution contains no workflows, runner configuration or credentials.
Image use and final merge remain subject to independent approval gates.
