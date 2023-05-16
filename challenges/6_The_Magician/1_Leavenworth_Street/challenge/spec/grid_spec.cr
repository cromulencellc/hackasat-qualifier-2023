require "./spec_helper"

require "../src/leavenworth/grid"

Spectator.describe Leavenworth::Grid do
  subject { described_class.new(3, 3) }

  it "is initialized with dimensions" do
    expect { described_class.new(3, 3) }.not_to raise_error
  end

  it "has a start" do
    expect(subject.start).to eq({0, 0})
    expect(subject[0, 0]).to eq Leavenworth::Cell::Start
  end

  it "has a finish" do
    expect(subject.finish).to eq({2, 2})
  end

  it "draws" do
    expect(subject.draw).to eq <<-DRAWN.strip
    SXX
    XXX
    XXF
    DRAWN
  end

  it "has fences" do
    expect(subject[-1, -1]).to eq Leavenworth::Cell::Wall
    expect(subject[1, 5]).to eq Leavenworth::Cell::Wall
  end

  it "finds an unvisited cell with a neighbor" do
    found = subject.unvisited_with_neighbor

    expect(found).to eq [{0, 2}, {2, 0}].to_set
  end

  it "finds untraversable neighbors" do
    expect(subject.untraversable_neighbors(0, 0))
      .to eq [{2, 0}, {0, 2}]
  end

  it "connects" do
    expect { subject.connect(subject.start, {2, 0}) }.not_to raise_error

    expect(subject.draw).to eq <<-DRAWN.strip
    S  
    XXX
    XXF
    DRAWN
  end
end
