require "./leavenworth/driver"

module Leavenworth
  VERSION = "0.1.0"

  def self.run!
    Driver.new.run!
  end
end

if /leavenworth$/ =~ PROGRAM_NAME
  Leavenworth.run!
end
