require "./spec_helper"

require "../src/leavenworth/driver"

Spectator.describe Leavenworth::Driver do
  it "initializes" do
    expect { described_class.new }.not_to raise_error
  end

  it "runs a subprocess"

  it "strips the environment from the subprocess"

  it "runs ten mazes of increasing size with the subprocess"
end
