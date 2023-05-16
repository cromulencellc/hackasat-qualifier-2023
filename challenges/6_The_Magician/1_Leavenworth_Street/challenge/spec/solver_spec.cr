require "./spec_helper"

require "../src/leavenworth/solver"

Spectator.describe Leavenworth::Solver do
  let(blank) { Leavenworth::Grid.new 7, 7 }
  let(big) { Leavenworth::Grid.new 51, 51 }
  let(gen) { Leavenworth::Generator.new blank }

  it "solves a default grid" do
    gen.generate!
    solver = described_class.new gen.grid

    expect(solver.solve!).to be, ->{ solver.grid.draw }
  end

  it "can solve 100 default grids" do
    100.times do
      biggen = Leavenworth::Generator.new blank.clone
      biggen.generate!

      solver = described_class.new biggen.grid

      expect(solver.solve!).to be, ->{ solver.grid.draw }
    end
  end

  it "can solve 100_000 default grids", :slow do
    100_000.times do |n|
      if 0 == (n % 1_000)
        print "#{n}\r"
      end

      biggen = Leavenworth::Generator.new blank.clone
      biggen.generate!

      solver = described_class.new biggen.grid

      expect(solver.solve!).to be, ->{ solver.grid.draw }
    end
  end

  it "solves a big grid" do
    biggen = Leavenworth::Generator.new big
    biggen.generate!

    solver = described_class.new biggen.grid

    expect(solver.solve!).to be, ->{ solver.grid.draw }
  end

  it "fails to solve an ungenerated grid" do
    solver = described_class.new blank

    expect(solver.solve!).not_to be, ->{ solver.grid.draw }
  end

  it "can solve 100 big grids" do
    100.times do
      biggen = Leavenworth::Generator.new big.clone
      biggen.generate!

      solver = described_class.new biggen.grid

      expect(solver.solve!).to be, ->{ solver.grid.draw }
    end
  end

  it "can solve 10_000 big grids", :slow do
    10_000.times do |n|
      if 0 == (n % 100)
        print "#{n}\r"
      end

      biggen = Leavenworth::Generator.new big.clone
      biggen.generate!

      solver = described_class.new biggen.grid

      expect(solver.solve!).to be, ->{ solver.grid.draw }
    end
  end
end
