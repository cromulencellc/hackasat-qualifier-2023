require "./grid"

module Leavenworth
  class Cursor
    enum Direction
      North = 0x4e # 'N'
      East  = 0x45 # 'E'
      South = 0x53 # 'S'
      West  = 0x57 # 'W'
    end

    property grid : Grid

    property position : Coord

    def initialize(@grid : Grid)
      @position = grid.start
    end

    def at_finish? : Bool
      self.position == grid.finish
    end

    def move(dir : Char)
      move Direction.new(dir.ord)
    end

    def move(dir : Direction) : Bool
      case dir
      in Direction::North
        try_move({0, -1})
      in Direction::East
        try_move({1, 0})
      in Direction::South
        try_move({0, 1})
      in Direction::West
        try_move({-1, 0})
      end
    end

    def try_move(c : Coord) : Bool
      updated_coord = {position[0] + c[0], position[1] + c[1]}
      case grid[updated_coord]
      in Cell::Room, Cell::Start, Cell::Finish, Cell::Live, Cell::Dead
        self.position = updated_coord
        return true
      in Cell::Wall
        return false
      end
    end
  end
end
