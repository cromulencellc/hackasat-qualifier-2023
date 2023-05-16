require "./grid"
require "./coord"

module Leavenworth
  class Generator
    property grid : Leavenworth::Grid
    property rng : Random

    def initialize(@grid : Leavenworth::Grid, @rng : Random = Random::Secure)
    end

    def generate!
      grid[grid.start] = Cell::Room
      grid[grid.finish] = Cell::Wall

      until (origins = grid.unvisited_with_neighbor).empty?
        origin = origins.first
        backhaul = grid.traversable_neighbors(origin).sample rng
        grid.connect(origin, backhaul)

        wander origin
      end

      grid[grid.start] = Cell::Start
      grid[grid.finish] = Cell::Finish
    end

    private def wander(c : Coord)
      possibilities = grid.untraversable_neighbors c
      return if possibilities.empty?

      possibility = possibilities.sample rng

      grid.connect c, possibility
      wander possibility
    end

    private def fixup(c : Coord)
      possibilities = grid.traversable_neighbors(c)
      possibility = possibilities.sample rng

      grid.connect c, possibility
    end
  end
end
