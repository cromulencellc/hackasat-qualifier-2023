require "./cell"
require "./coord"

module Leavenworth
  class Grid
    property width : UInt8
    property height : UInt8

    alias Row = Slice(Cell)

    property cells : Array(Row)

    def initialize(@width : UInt8, @height : UInt8, fill = Cell::Wall)
      @cells = height.times.map { Slice.new(width.to_i32, fill) }.to_a
      cells[0][0] = Cell::Start
      cells[height - 1][width - 1] = Cell::Finish
    end

    def clone
      nuevo = Grid.new @width, @height
      nuevo.cells = @cells.clone

      return nuevo
    end

    def [](c : Coord)
      self[c[0], c[1]]
    end

    def [](x : Int, y : Int)
      return Cell::Wall if (x < 0) || (y < 0)
      return Cell::Wall if (x >= @width) || (y >= @height)

      return cells[y][x]
    end

    def in_bounds?(c : Coord)
      return false if (c[0] < 0) || (c[1] < 0)
      return false if (c[0] >= @width) || (c[1] >= @height)

      return true
    end

    def []=(c : Coord, nuevo : Cell)
      unless in_bounds?(c)
        raise "#{c.inspect} out of bounds"
      end

      cells[c[1]][c[0]] = nuevo
    end

    def neighbor_coords(c : Coord) : Array(Coord)
      neighbor_coords(c[0], c[1])
    end

    def neighbor_coords(x : Int32, y : Int32) : Array(Coord)
      [{x - 2, y}, {x + 2, y}, {x, y - 2}, {x, y + 2}]
        .select { |c| in_bounds? c }
    end

    def traversable_neighbors(c : Coord)
      traversable_neighbors(c[0], c[1])
    end

    def traversable_neighbors(x, y)
      neighbor_coords(x, y)
        .select { |c| self[*c] != Cell::Wall }
    end

    def untraversable_neighbors(c : Coord)
      untraversable_neighbors(c[0], c[1])
    end

    def untraversable_neighbors(x, y)
      neighbor_coords(x, y)
        .select { |c| self[*c] == Cell::Wall }
    end

    def walkable_neighbors(c : Coord)
      neighbor_coords(c)
        .select do |n|
          nc = self[n]
          next false if nc == Cell::Wall
          next false if nc == Cell::Live
          next false if nc == Cell::Dead

          mc = self[midpoint(c, n)]
          next false if mc == Cell::Wall

          true
        end
    end

    def start : Coord
      {0, 0}
    end

    def finish : Coord
      {width.to_i32 - 1, height.to_i32 - 1}
    end

    def draw
      cells.map { |c| String.new(c.map(&.to_u8), "UTF8") }.join("\n")
    end

    def unvisited_with_neighbor : Set(Coord)
      height.times.map do |y|
        next nil if y.odd?
        width.times.map do |x|
          next nil if x.odd?

          next nil unless self[x, y] == Cell::Wall
          # is wall

          next nil if traversable_neighbors(x, y).empty?
          # has a traersable neighbor

          next {x.to_i32, y.to_i32}
        end.to_a.compact
      end.to_a.compact.flatten.to_set
    end

    def midpoint(c1 : Coord, c2 : Coord) : Coord
      {c1[0] + ((c2[0] - c1[0]) >> 1),
       c1[1] + ((c2[1] - c1[1]) >> 1)}
    end

    def connect(c1 : Coord, c2 : Coord)
      midpoint = midpoint(c1, c2)

      self[c1] = Cell::Room if Cell::Wall == self[c1]
      self[midpoint] = Cell::Room if Cell::Wall == self[midpoint]
      self[c2] = Cell::Room if Cell::Wall == self[c2]
    end
  end
end
