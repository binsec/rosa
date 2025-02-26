# Release checklist

01. Ensure local `main` is up to date with respect to `origin/main`.

02. Check for dependency updates (via `cargo update`).

03. Update `VERSION` and the version field in `Cargo.toml`; this should simply be removing the
    `"-dev"` part.

04. Run the following:

    1. `cargo check`
    2. `cargo fmt`
    3. `cargo clippy`
    4. `cargo build --release`
    5. `cargo test`
    6. `cargo doc`

    They should all succeed.

05. Run `mdbook serve doc` and peruse the documentation to make sure it looks correct.

06. Update `CHANGELOG.md`.

07. Build the Docker image with the `build.sh` script and make sure it succeeds (check that an image
    with the right version has been created with `docker images`).

08. Run the Docker image with the `run.sh` script. In the container, run
    `rosa /root/rosa/examples/sudo/config/sudo-backdoored.toml`; this should succeed, and you should
    see ROSA starting up and showing the status screen. You can also investigate the findings to see
    if everything works as expected.

09. Commit the changes and tag the commit with the version. For example, for version `X.Y.Z`, tag
    the commit with `git tag -a X.Y.Z`.

10. Push the commit and the changes.

11. Tag and push the Docker image: `docker tag rosa:X.Y.Z plumtrie/rosa:X.Y.Z`,
    `docker push plumtrie/rosa:X.Y.Z`.

12. Tag and push the new image as "latest": `docker tag plumtrie/rosa:X.Y.Z plumtrie/rosa:latest`,
    `docker push plumtrie/rosa:latest`.

13. Prepare for the next version by bumping the PATCH number in the version and appending `"-dev"`.
    This means that `"1.2.3"` should become `"1.2.4-dev"`.
