module Leavenworth
  enum Cell : UInt8
    # generation
    Wall   = 0x58 # X
    Start  = 0x53 # S
    Finish = 0x46 # F
    Room   = 0x20 # space

    # solve
    Live = 0x7E # ~
    Dead = 0x5F # _
  end
end
