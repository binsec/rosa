# Release checklist
1. Ensure local `main` is up to date with respect to `origin/main`.
2. Check for dependency updates (via `cargo update`).
3. Update `VERSION` and the version field in `Cargo.toml`; this should simply be removing the
   `"-dev"` part.
4. Run the following:
    1. `cargo check`
    2. `cargo clippy`
    3. `cargo build --release`
    4. `cargo test`
    5. `cargo doc`
    
    They should all succeed.
5. Run `mdbook serve doc` and peruse the documentation to make sure it looks correct.
6. Build the Docker image with the `build.sh` script and make sure it succeeds (check that an image
   with the right version has been created with `docker images`).
7. Run the Docker image with the `run.sh` script. In the container, run `rosa
   /root/rosa/examples/sudo/config/sudo-backdoored.toml`; this should succeed, and you should see
   ROSA starting up and showing the status screen. You can also investigate the findings to see if
   everything works as expected.
8. Commit the changes and tag the commit with the version. For example, for version `X.Y.Z`, tag
   the commit with `git tag -a X.Y.Z`.
9. Push the commit and the changes.
10. Tag and push the Docker image: `docker tag rosa:X.Y.Z plumtrie/rosa:X.Y.Z`, `docker push
    plumtrie/rosa:X.Y.Z`.
11. Prepare for the next version by bumping the PATCH number in the version and appending `"-dev"`.
    This means that `"1.2.3"` should become `"1.2.4-dev"`.
