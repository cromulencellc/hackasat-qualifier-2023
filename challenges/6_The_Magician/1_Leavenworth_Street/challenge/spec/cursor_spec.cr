require "./spec_helper"

require "../src/leavenworth/cursor"

Spectator.describe Leavenworth::Cursor do
  let(grid) { Leavenworth::Grid.new 11, 11 }
  let(empty_grid) { Leavenworth::Grid.new 3, 3, fill: Leavenworth::Cell::Room }

  subject { Leavenworth::Cursor.new empty_grid }

  it "starts at the start" do
    expect(subject.position).to eq empty_grid.start
  end

  it "accepts input" do
    expect(subject.position).to eq({0, 0})
    expect(subject.move Leavenworth::Cursor::Direction::East).to be
    expect(subject.position).to eq({1, 0})
    expect(subject.move Leavenworth::Cursor::Direction::South).to be
    expect(subject.position).to eq({1, 1})
    expect(subject.move 'W').to be
    expect(subject.position).to eq({0, 1})
    expect(subject.move 'N').to be
    expect(subject.position).to eq({0, 0})
  end

  it "refuses to phase through a wall" do
    expect(subject.position).to eq({0, 0})
    expect(subject.move 'N').not_to be
    expect(subject.position).to eq({0, 0})
  end

  it "finishes when the cursor hits the finish" do
    expect(subject.at_finish?).not_to be
    2.times do
      expect(subject.move 'E').to be
      expect(subject.move 'S').to be
    end
    expect(subject.at_finish?).to be
  end
end
