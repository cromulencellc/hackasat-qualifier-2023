# Hack-a-Sat 4 Qualifier

`Approved for Public Release, Distribution Unlimited: AFRL-2023-2277 before this sentence on the github This repository contains the open source release for the Hack-a-Sat 4 qualifier from 2023.`

This repository contains the open source release for the Hack-a-Sat 4 qualifier from 2023.

Released artifacts include:

* Source code for all challenges
* Source code for all challenge solutions
* Infrastructure to build all challenges and their solutions
* Notes on how to build and solve challenges

Released artifacts *do not* include:

* Infrastructure used to host and run the game
* Source code for the score board
* Source code for the "ticket taker" or "lifecycle manager" (used to host
  randomized challenges within the live game infrastructure)
* Source code for the "sat solver" (used to test challenges before deployment)
* Source code for the "async/lounge" (used to host async challenges and accept inputs files from users to add to the queue)

## Repository Structure ##

The infrastructure for Hack-a-Sat 2023 deployed challenges from self-contained
[Docker](https://www.docker.com/) images. Each challenge has an internal
name that is used to refer to that challenge's containers. These names are not
necessarily the same as the name that was used on the scoreboard. Folders
within this repository are named according to each challenge's internal name,
rather than its external one.

The following is a mapping of all names by category:

| Category | Challenge Name | Links |
| ------ | ------ | ------ |
|The Kitchen|The Freezer| [link](./challenges/0_The_Kitchen/0_The_Freezer/) |
|The Kitchen|The Microwave| [link](./challenges/0_The_Kitchen/1_The_Microwave/) |
|The Kitchen|The Stove| [link](./challenges/0_The_Kitchen/2_The_Stove/) |
|The Kitchen|A Sink| [link](./challenges/0_The_Kitchen/) |
|Aerocapture the Flag|GGs| [link](./challenges/1_Aerocapture_The_Flag/0_GGs/) |
|Aerocapture the Flag|Find Your Center| [link](./challenges/1_Aerocapture_The_Flag/1_Find_Your_Center/) |
|Aerocapture the Flag|Terraforming Mars| [link](./challenges/1_Aerocapture_The_Flag/2_Teraforming_Mars/) |
|Aerocapture the Flag|TLE| [link](./challenges/1_Aerocapture_The_Flag/3_TLE/) |
|Can't Stop the Signal, Mal|QAM| [link](./challenges/2_Cant_Stop_The_Signal_Mal/0_QAM/) |
|Can't Stop the Signal, Mal|Dashing| [link](./challenges/2_Cant_Stop_The_Signal_Mal/1_Dashing/) |
|Can't Stop the Signal, Mal|FAUXY Lady| [link](./challenges/2_Cant_Stop_The_Signal_Mal/2_Fauxy_Lady/) |
|Can't Stop the Signal, Mal|Dark Side of the Dishy| [link](./challenges/2_Cant_Stop_The_Signal_Mal/3_Dark_Side_of_the_Dishy/) |
|Pure Pwnage|RISC-V Smash Baby| [link](./challenges/3_Pure_Pwnage/0_RISC-V-Smash-Baby/) |
|Pure Pwnage|Warning| [link](./challenges/3_Pure_Pwnage/1_Warning/) |
|Pure Pwnage|dROP Baby| [link](./challenges/3_Pure_Pwnage/2_dROP_Baby/) |
|Pure Pwnage|Magic Space Bussin| [link](./challenges/3_Pure_Pwnage/3_Magic_Space_Bussin/) |
|Pure Pwnage|Spectrel Imaging| [link](./challenges/3_Pure_Pwnage/4_Spectrel_Imaging/) |
|Pure Pwnage|Kalman At Me Bro| [link](./challenges/3_Pure_Pwnage/5_Kalman_At_Me_Bro/) |
|Anomaly Review Bored|Contact| [link](./challenges/4_Anomoly_Review_Bored/0_Contact/) |
|Anomaly Review Bored|You've Been Promoted!| [link](./challenges/4_Anomoly_Review_Bored/1_Youve_Been_Promoted/) |
|Van Halen Radiation Belt|Based Emoji| [link](./challenges/5_Van_Halen_Radiation_Belt/0_Based_Emoji/) |
|Van Halen Radiation Belt|Meet Me at Midway| [link](./challenges/5_Van_Halen_Radiation_Belt/1_Meet_Me_At_Midway/) |
|Van Halen Radiation Belt|Signals from Trisolaris| [link](./challenges/5_Van_Halen_Radiation_Belt/2_Signals_From_Trisolaris/) |
|Van Halen Radiation Belt|Quantum| [link](./challenges/5_Van_Halen_Radiation_Belt/3_Quantum/) |
|The Magician|As Below| [link](./challenges/6_The_Magician/0_As_Below/) |
|The Magician|Leavenworth Stree| [link](./challenges/6_The_Magician/1_Leavenworth_Street/) |
|The Magician|Hyde Street| [link](./challenges/6_The_Magician/2_Hyde_Street/) |
|The Magician|So Above| [link](./challenges/6_The_Magician/3_So_Above/) |

The `generator-base` folder is included to build the base image for all
challenges that use a generator (see below).


## Building and Deploying Challenges ##

For instructions on how to build each challenge's Docker images, please refer
to each folder's `README.md`. Each challenge may have up to 3 separate images:

* `generator` - Used to generate any static files necessary to give to teams.
* `challenge` - Used to host the actual challenge on the game infrastructure.
* `solver` - Used to ensure the challenge would be solvable for a given team.

**Base Python/GnuRadio/Basilisk Images**

Some challenge containers pull from a prebuilt base image that includes either the 
pyctf library, basilisk or gnuRadio. These base images must be built before some 
challenge containers that depend on them can be built. To do this:

```bash
pushd challenges/base_challenges/
./build.sh
popd
```

Once this build script is completed, there should be at least 7 images built:

```bash
> docker images | grep -i 'has4\/quals\/challenges\/ctf' | wc -l
7
```

Now it should be possible to build challenges that depend on any of the base 
containers.

**Building/Running Challenges**

Nearly all challenges have a Makefile that defines several targets. Typically
the first target that must be built in a challenge directory is `make build`.

For example:

To build [The_Microwave](challenges/0_The_Kitchen/1_The_Microwave/)

```bash
pushd challenges/0_The_Kitchen/1_The_Microwave
make build
popd
```

Now the challenge image is build. For static or generator challenges, this will
build the binaries necessary to run the challenge in the next step.
To use the `make challenge` target, you must have socat installed. This can be
installed on debian-based systems using:

`sudo apt install socat`

To run the challenge:

```bash
> cd challenges/0_The_Kitchen/1_The_Microwave
> make challenge

"To connect: nc localhost 12345"
```

This will start up a container served through an instance of socat. Socat will
be listening on localhost:12345. Now run netcat to connect to that listener:

```bash
> nc localhost 12345

Math problem available at http://localhost:7000/math
What is the solution to the math problem? 
```

Now the challenge is running!

All challenges are ran in docker containers. You can kill a challenge through
the `docker kill` command.

All socat instances pipe their output to a file named `log` in the same directory.
If a challenge seems to have crashed, or is being unresponsive, check the log 
file. It may help with debugging your solver or running the challenge.

```bash
> cat log
< 2023/04/06 20:51:40.610706  length=95 from=0 to=94
Math problem available at http://localhost:7000/math
What is the solution to the math problem? Traceback (most recent call last):
  File "/challenge/challenge.py", line 25, in <module>
    challenge()
  File "/usr/local/lib/python3.10/site-packages/ctf/timeout.py", line 29, in wrapper
    result = func(*args, **kwargs)
  File "/challenge/challenge.py", line 14, in challenge
    answer = IO.input_int("What is the solution to the math problem? ")
  File "/usr/local/lib/python3.10/site-packages/ctf/io.py", line 97, in input_int
    strInput = input(msg)
  File "/usr/local/lib/python3.10/site-packages/ctf/timeout.py", line 23, in _handle_timeout
    raise TimeoutError(error_message)
ctf.timeout.TimeoutError: Timer expired
2023/04/06 20:53:41 socat[1444852] E waitpid(): child 1444893 exited with status 1
```

### Missing Infrastructure ###

This repository does not contain the `ticket-taker`, `lifecycle-manager`,
`sat-solver` or `async/lounge` programs (or their source code).

During the live Hack-a-Sat 4 qualifier, challenges were deployed with a
program called `ticket-taker`. This program would take a supplied ticket and
use it to generate a seed value and flag specific to that ticket. It would then
launch an instance of the challenge container, passing any options necessary
via environment variables.

Using `ticket-taker` posed a problem for certain challenges: External tools we
expected players to use, like Google Maps, don't understand "tickets". A
second program called `lifecycle-manager` was used for these challenges.
`ticket-taker` would launch an instance of `lifecycle-manager` to "manage" the
connection between the player and the challenge after the player authenticated
with their ticket.

The commands below are from our internal test tool (called `sat-solver`), that
was capable of testing the solver against a specific seed in a managed
environment without `ticket-taker` or `lifecycle-manager`. These commands
should be sufficient for anyone using this repository to quickly host
challenges locally for testing.

[This file](tickets.csv) can
be used as a "decoder ring" for turning tickets from the live event into seed
values that allow you to run the same copy of the challenge your team got in
the 2023 qualifier.

### Generators ###

These were run in a job queue prior to the release of a challenge to generate
the unique status files for each team's challenge seed:

```sh
docker run -t --rm -v <dir>:/out -e SEED=<seed> -e FLAG=<flag> <container>:generator
```

* `dir` is the output directory on the host where you want generated files
  to be stored.
* `seed` is the random seed you want files to be generated for.
* `flag` is the flag you expect the team to submit to the scoreboard.
* `container` is the internal name of the challenge (see above).

Generators were typically built off of the `generator-base` Docker image. As a
result, you'll need to build the image in the `generator-base` folder before
building any generator images.

### Challenges ###

These were run on hardened AWS VMs that were provisioned by a central
[Puppet](https://puppet.com/) Master. Every VM only hosted a single challenge.
Multiple VMs were used with a round-robin DNS loadbalancer to spread connections
across all VMs provisioned for that challenge.

Puppet would install [`xinetd`](https://en.wikipedia.org/wiki/Xinetd), which
would open up a single port for incoming connections for `ticket-taker`.
`ticket-taker` would be responsible for executing one of the commands below
based on a configuration file after the player's ticket was verified:

```sh
# use this if the challenge only needs basic options
docker run --rm -i -e SEED=<seed> -e FLAG=<flag> <container>:challenge

# use this if the challenge needs generated files to run
docker run --rm -i -e DIR=/mnt -v <dir>:/mnt -e SEED=<seed> -e FLAG=<flag> <container>:challenge

# use this if the challenge is required to have its connections managed
docker run --rm -i -e SERVICE_HOST=<host> -e SERVICE_PORT=<port> -e SEED=<seed> -e FLAG=<flag> <container>:challenge

# use this if the challenge needs both generated files and a managed connection
docker run --rm -i -e DIR=/mnt -v <dir>:/mnt -e SERVICE_HOST=<host> -e SERVICE_PORT=<port> -e SEED=<seed> -e FLAG=<flag> <container>:challenge
```

* `seed` is the random seed to use when running the challenge.
* `flag` is the flag you expect the team to submit to the scoreboard.
* `container` is the internal name of the challenge (see above).
* `host` is the IP or address of the host this container is running on.
* `port` is the additional port the challenge should open.
* `dir` is the directory on the host where generated files are stored.

To re-host these challenges *without* `xinetd`, you can use `socat` like so:

```sh
# remember to escape any colons (":") in the commands above with backslashes!
socat -v tcp-listen:<port>,reuseaddr "exec:<command from above>"
```

### Solvers ###

These were run in batches on a server with tons of cores to ensure every team
would be able to solve their randomized version of each challenge. They were
also run any time a team wanted verification that a challenge was working as
intended during the live game.

```sh
# use this if the solver only needs basic options
docker run -it --rm -e HOST=<host> -e PORT=<port> <container>:solver

# use this if the solver needs generated files to run
docker run -it --rm -e HOST=<host> -e PORT=<port> -e DIR=/mnt -v <dir>:/mnt <container>:solver

# use this if you want to solve with a specific ticket
docker run -it --rm -e HOST=<host> -e PORT=<port> -e TICKET=<ticket> <container>:solver

# use this if you want to solve with a specific ticket and need generated files
docker run -it --rm -e HOST=<host> -e PORT=<port> -e DIR=/mnt -v <dir>:/mnt -e TICKET=<ticket> <container>:solver
```

* `seed` is the random seed of the challenge you're trying to solve.
* `ticket` is the ticket for your team.
* `container` is the internal name of the challenge (see above).
* `host` is the IP or address of the challenge host.
* `port` is the port on the challenge host for this challenge.
* `dir` is the directory on the host where generated files are stored.

It should be noted that these solvers implement *a* solution for their
challenge, not *the* solution. Many challenges had alternative ways of solving
them (some easier, some harder) that were not tested by (and, in some cases, not
intended by) the organizers.


## License ##

Challenges in this repository are provided as-is under the MIT license.
See [LICENSE.md](LICENSE.md) for more details.


## Contact ##

Questions, comments, or concerns can be sent to `hackasat[at]cromulence.com`.