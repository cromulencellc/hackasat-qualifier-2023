require "spectator"

require "../src/leavenworth"

Spectator.configure do |config|
  unless ENV["SLOW"]?
    config.add_node_reject(Spectator::TagNodeFilter.new("slow"))
  end

  config.formatter = Spectator::Formatting::DocumentFormatter.new
end
