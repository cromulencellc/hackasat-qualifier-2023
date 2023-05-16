require "./spec_helper"

require "../src/leavenworth/generator"

Spectator.describe Leavenworth::Generator do
  let(grid) { Leavenworth::Grid.new(5, 5) }
  let(big_grid) { Leavenworth::Grid.new(15, 15) }
  let(fixed_rng) { Random::PCG32.new(0) }
  let(csprng) { Random::Secure.new }

  subject { described_class.new(grid, rng: fixed_rng) }

  it "is initializable with a grid" do
    expect { described_class.new(grid) }.not_to raise_error
  end

  it "is initializable with a grid and rng" do
    expect { described_class.new(grid, fixed_rng) }.not_to raise_error
  end

  it "generates a maze" do
    expect { subject.generate! }.not_to raise_error

    expect(grid.draw).to eq <<-DRAWN
    S    
    XXXX 
         
     XXXX
        F
    DRAWN
  end

  it "generates a big maze" do
    big_gen = described_class.new(big_grid)

    expect { big_gen.generate! }.not_to raise_error

    got = big_grid.draw

    expect(got).to be_a String
  end
end
