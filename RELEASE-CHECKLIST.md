# Release checklist

01. Ensure local `main` is up to date with respect to `origin/main`.
02. Run pre-commit checks:
    ```console
    $ pre-commit run --all-files
    ```
03. Run tests:
    ```console
    $ cargo test
    ```
04. Check for dependency updates (via `cargo update`).
05. Update `VERSION` and the version field in `Cargo.toml`; this should simply be removing the
    `"-dev"` part.
06. Run `mdbook serve doc` and peruse the documentation to make sure it looks correct.
07. Update `CHANGELOG.md`.
08. Build the Docker image with the `build.sh` script and make sure it succeeds (check that an image
    with the right version has been created with `docker images`).
09. Run the Docker image with the `run.sh` script. In the container, run
    `rosa /root/rosa/examples/sudo/config/sudo-backdoored.toml`; this should succeed, and you should
    see ROSA starting up and showing the status screen. You can also investigate the findings to see
    if everything works as expected.
10. Commit the changes and tag the commit with the version. For example, for version `X.Y.Z`, tag
    the commit with `git tag -a X.Y.Z`.
11. Push the commit **without pushing the tag** via `git push --no-follow-tags`. Wait for the CI to
    finish, and continue to the next steps only if the CI succeeds.
12. Push the tag with `git push --tags`.
13. Tag and push the Docker image: `docker tag rosa:X.Y.Z plumtrie/rosa:X.Y.Z`,
    `docker push plumtrie/rosa:X.Y.Z`.
14. Tag and push the new image as "latest": `docker tag plumtrie/rosa:X.Y.Z plumtrie/rosa:latest`,
    `docker push plumtrie/rosa:latest`.
15. Prepare for the next version by bumping the PATCH number in the version and appending `"-dev"`.
    This means that `"1.2.3"` should become `"1.2.4-dev"`.
