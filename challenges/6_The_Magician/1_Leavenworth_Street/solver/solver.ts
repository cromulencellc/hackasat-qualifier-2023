// deno-lint-ignore-file prefer-const
import { BufReader } from "https://deno.land/std@0.178.0/io/buf_reader.ts"

let debug: (_jawn: any) => void

const enc = new TextEncoder()
const dec = new TextDecoder()

if (await Deno.permissions.query({name: "env", variable: "SOLVER_DEBUG"}) && 
  Deno.env.get('SOLVER_DEBUG')) {

    debug = (jawn: any) => {
      Deno.stderr.writeSync(enc.encode(Deno.inspect(jawn) + "\n"))
    }
} else {
  debug = (_jawn: any) => {}
}

let reader = new BufReader(Deno.stdin)


async function readInt() : Promise<number> {
  let buf = await reader.readLine()
  if (null == buf) return -1
  if (buf.more) return -1

  return parseInt(dec.decode(buf.line))
}

async function readMaze(maze_len: number) : Promise<Uint8Array> {
  let got = 0
  let maze_buf = new Uint8Array(maze_len)
  let inner_buf = maze_buf.buffer
  while (got < maze_len) {
    let temp_buf = new Uint8Array(inner_buf, got)
    let cur = await reader.read(temp_buf)

    if (null == cur) {
      debug(`got null when trying to read ${maze_len} after ${got}`)
      Deno.exit(1)
    }

    got += cur
  }

  return maze_buf
}

let maze_len = await readInt()

debug(maze_len)

let maze_buf = await readMaze(maze_len)

let width  = maze_buf.findIndex(val => 0x0a == val)
let without_newlines = maze_buf.filter(val => 0x0a != val)

let height = (without_newlines.length / width)

debug(`${maze_buf.length} becomes ${without_newlines.length} becomes ${width} * ${height}`)

enum Cell {
  Wall   = 0x58, // X
  Start  = 0x53, // S
  Finish = 0x46, // F
  Room   = 0x20, // space

  Seen   = 0x7E  // ~
}

enum Direction {
  North = 0x4e, // 'N'
  East = 0x45, // 'E'
  South = 0x53, // 'S'
  West = 0x57, // 'W'
}

function reverse_dir(d : Direction) : Direction {
  switch(d) {
    case Direction.North: return Direction.South
    case Direction.East: return Direction.West
    case Direction.South: return Direction.North
    case Direction.West: return Direction.East
  }
}

type Coord = {
  x: number
  y: number
}

let maze : Cell[][] = []

let start : Coord
let finish : Coord

for (let y = 0; y < height; y++) {
  let j = y * width
  maze[y] = []
  for (let x = 0; x < width; x++) {
    let i = j + x
    let c : Cell = without_newlines[i]
    if (Cell.Start == c) {
      start = {x: x, y: y}
    } else if (Cell.Finish == c) {
      finish = {x: x, y: y}
    }
    maze[y][x] = c
  }
}

if ((undefined == start) || (undefined == finish)) {
  debug("either start or finish weren't there")
  Deno.exit(1)
}

debug(start)
debug(finish)

type Path = {
  c: Coord
  h: Direction[]
}

let to_traverse : Path[] = [{c: start, h: []}]

function possible_paths(p : Path) : Path[] {
  let c = p.c

  return [
    {
      c: {x: c.x, y: c.y - 1},
      h: p.h.concat(Direction.North)
    },
    
    {
      c: {x: c.x + 1, y: c.y},
      h: p.h.concat(Direction.East)
    },
    
    {
      c: {x: c.x, y: c.y + 1},
      h: p.h.concat(Direction.South)
    },

    {
      c: {x: c.x - 1, y: c.y},
      h: p.h.concat(Direction.West)
    }
  ].
  filter(p => {
    return !((p.c.x < 0) || (p.c.x >= width) || (p.c.y < 0) || (p.c.y >= height))
  }).
  filter(p => {
    if (1 >= p.h.length) return true
    return p.h[0] != reverse_dir(p.h[1])
  })
}

let found_path : Direction[]

while (to_traverse.length > 0) {
  let cur = to_traverse.shift()
  if (!cur) {
    debug("ran out of traversables, shouldn't happen")
    Deno.exit(1)
  }
  if (Cell.Finish == maze[cur.c.y][cur.c.x]) {
    debug("found the end")
    debug(cur)
    found_path = cur.h
    break
  }
  
  maze[cur.c.y][cur.c.x] = Cell.Seen

  let pos = possible_paths(cur).
    filter(p => {
      if (Cell.Wall == maze[p.c.y][p.c.x]) return false
      if (Cell.Seen == maze[p.c.y][p.c.x]) return false

      return true
    })
  
  // debug(pos)
  // debug(`${to_traverse.length} + ${pos.length}`)

  to_traverse.push(...pos)
}

if (undefined == found_path) {
  debug("got to the end, rip")
  Deno.exit(1)
}

debug(dec.decode(new Uint8Array(found_path)))

for (let d of found_path) {
  let a = new Uint8Array([d])
  // debug(dec.decode(a))
  await Deno.stdout.write(a)
}
