# Using ROSA in a Docker container
The recommended way to use ROSA is in a Docker container, to avoid having to build dependencies
(such as AFL++).

You can simply pull the existing ROSA Docker image by running:
```console
$ docker pull <TODO ADDRESS>
```
Then, you can run a container using that image by running:
```console
$ docker run -ti --rm -e "COLORTERM=truecolor" -p 4000:4000 <TODO IMAGE NAME>
```
Note that this command will start an interactive session within the container, and that exiting
the container will trigger its removal. It will also forward any traffic to port 4000 on the host
to port 4000 on the guest, and serve the documentation on that port; this means you can consult the
documentation on <http://localhost:4000> on the host while the Docker container is running.

## Building the Docker image
If you wish to build the Docker image on your machine, you can use the helper `build.sh` script,
which will automatically tag the image with the current version. See the script itself for more
information.

Before running the script (or simply `docker build ...`), make sure that you have cloned **all of
the submodules** used in this repo. You can do this either by cloning the repo with
`--recurse-submodules`, or by running `git submodule update --init --recursive` post-cloning.

<div class="warning">
    Be advised that the build might take some time, especially including the time it takes to clone
    all of the submodules.
</div>

Once the Docker image is built, the `run.sh` convenience script may be used to run it. Generally,
released versions of the image will be tagged, so you can run `git checkout <TAG>` and run
`./build.sh` and `./run.sh` to build and run a specific version of the image.
