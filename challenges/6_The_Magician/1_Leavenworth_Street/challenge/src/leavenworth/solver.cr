require "./grid"

module Leavenworth
  class Solver
    property grid : Grid

    property to_traverse : Array(Coord) = [] of Coord

    def initialize(grid : Grid)
      @grid = grid.clone
    end

    def solve!
      to_traverse << @grid.start

      until to_traverse.empty?
        cur = to_traverse.shift
        walkable = grid.walkable_neighbors(cur)

        if walkable.empty?
          grid[cur] = Cell::Dead
          next
        end

        walkable.each do |w|
          grid[grid.midpoint(cur, w)] = Cell::Live

          if grid[w] == Cell::Finish
            return true
          end

          grid[w] = Cell::Live
          to_traverse.push w
        end
      end

      return false
    end
  end
end
