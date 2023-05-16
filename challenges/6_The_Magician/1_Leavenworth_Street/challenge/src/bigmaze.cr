require "./leavenworth/generator"
require "./leavenworth/grid"
require "./leavenworth/solver"

x_size = (ARGV[1] rescue 25).to_u8
y_size = (ARGV[2] rescue x_size).to_u8

loop do
  grid = Leavenworth::Grid.new x_size, y_size
  gen = Leavenworth::Generator.new grid
  gen.generate!

  sol = Leavenworth::Solver.new grid
  if sol.solve!
    puts grid.draw

    if ENV["SPOILERS"]?
      puts
      puts sol.grid.draw
    end
    break
  end
end
