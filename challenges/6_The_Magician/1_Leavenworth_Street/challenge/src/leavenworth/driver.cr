require "log"

require "./cursor"
require "./generator"
require "./grid"
require "./solver"

module Leavenworth
  class Driver
    @process : Process?
    @process_started = Channel(Bool).new(1)
    @process_error = Channel(Exception).new(1)

    @grid : Grid?

    def run!
      runs = (ENV["RUNS"]? || 10).to_u8

      runs.times do |r|
        Log.info { "starting run #{r}" }
        size = (7 + (2 * r)).to_u8

        start_subprocess

        Log.debug { "cooking maze size #{size}" }

        make_maze(size)

        Log.debug { "waiting for subprocess start" }

        if (!@process_started.receive)
          Log.fatal { "Process didn't start right?" }
          Log.fatal { @process_error.receive }
          raise "process didn't start right"
        end

        send_maze

        accept_solution

        kill_subprocess
      end

      puts ENV["FLAG"]? || "pretend the flag is here"
    end

    private def start_subprocess
      did_start = false

      spawn do
        begin
          @process = process = Process.new(command: "/usr/bin/doas",
            args: %w{-n -u deno /usr/bin/deno run --cached-only --allow-read=/deno-dir --allow-env=SOLVER_DEBUG /solver/solver.ts},
            env: {"SOLVER_DEBUG" => ENV["SOLVER_DEBUG"]?},
            output: Process::Redirect::Pipe,
            input: Process::Redirect::Pipe,
            error: Process::Redirect::Inherit
          )

          Log.info { "Started player process #{process.pid}" }

          did_start = true
          @process_started.send(true)
        rescue ex
          @process_error.send ex
          @process_started.send false
        end
      end
    end

    private def make_maze(size)
      loop do
        grid = Grid.new(size, size)
        generator = Generator.new grid
        generator.generate!

        solver = Solver.new grid.clone
        if solver.solve!
          return @grid = grid
        end
      end
    end

    private def send_maze
      unless (grid = @grid) && (process = @process) && process.exists?
        Log.fatal { @grid.inspect }
        Log.fatal { @process.inspect }
        raise "couldn't send_maze"
      end

      maze_data = grid.draw
      process.input.puts maze_data.bytesize.to_s
      process.input.print maze_data
      puts maze_data
    end

    private def accept_solution
      unless (grid = @grid) && (process = @process) && process.exists?
        Log.fatal { @grid.inspect }
        Log.fatal { @process.inspect }
        raise "couldn't accept_solution"
      end

      cursor = Cursor.new grid

      loop do
        move_b = process.output.read_utf8_byte

        if move_b.nil?
          Log.fatal { "got nil when wanted move" }
          kill_subprocess
          exit 1
        end

        valid_move = cursor.move move_b.chr
        unless valid_move
          Log.fatal { "invalid move #{move_b} at #{cursor.position}" }
          kill_subprocess
          exit 1
        end

        if cursor.at_finish?
          Log.info { "finished! woo" }
          break
        end
      end
    end

    private def kill_subprocess
      if (process = @process) && process.exists?
        Log.info { "killing #{process.pid}" }
        process.signal Signal::KILL
        process.wait
      end
    end
  end
end
