# Zerve

Toy files server implementation written in zig 0.13.0

## Installation

```sh
git clone https://github.com/alphatechnolog/zerve zerve
cd zerve
sudo zig build -p /usr/local -Doptimize=ReleaseFast install
```

## Usage

Just call `zerve` on the directory you wanna start the server, and zerve will start
listening at port 8000 sharing those files only. You can then open your browser using the
address [http://localhost:8000](http://localhost:8000) to start browsing files.

## TODO

- [ ] Allow specifying folder from config file or flags
- [ ] Allow specifying the port of the server
- [ ] Share the server across the network
