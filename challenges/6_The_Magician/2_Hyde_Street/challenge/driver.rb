require 'digest'
require 'fileutils'
require 'logger'
require 'json'
require 'set'

UINT32_MAX = 0xffffffff

NUMBER_TO_GENERATE = 10

def num_in_range(op)
  case op
  when :/
    rand(2..16)
  when :*
    rand(2..32)
  when :-
    rand(0..256)
  when :+
    rand(0..16384)
  else
    fail "couldn't num_in_range for #{op}"
  end
end


FileUtils.mkdir_p "challs"

dest = File.join __dir__, 'src', 'quick_maths.c'

NUMBER_TO_GENERATE.times do |n|
  out_f = File.open dest, 'w'

  out_f.puts <<~EOS.strip
  #include <stdint.h>
  #include <stdbool.h>

  bool quick_maths(uint32_t run) {
  EOS

  want = rand(0..UINT32_MAX)
  run = want

  rand(10..20).times do
    stmt = nil
    result = nil

    loop do
      # skipping multiplication for now; idiv vs. fdiv ;_;
      operation = %i{+ - /}.sample 
      operand = num_in_range(operation)

      result = run.send operation, operand

      # next here loops again
      next if result >= UINT32_MAX
      next if result <= 0

      stmt = "run = run #{operation} #{operand};"
      stmt += " // #{result}" if ENV['CHALLENGE_DEV_DEBUG']
      break
    end

    out_f.puts stmt
    run = result
  end


  out_f.puts <<~EOS.strip
  return (run == #{ run });
  }
  EOS

  out_f.close

  `make clean all`


  size = `wc -c build/ominous_etude`.split[0].to_i
  digest = `sha256sum build/ominous_etude`.split[0]

  new_omen_name = "generated"
  FileUtils.mv 'build/ominous_etude', "challs/#{new_omen_name}"
  FileUtils.mv dest, "challs/#{new_omen_name}.c"

  $stderr.puts JSON.dump({
    'sha256' => digest,
    'size' => size,
    'answer' => want.to_s
  })

  got = nil

  
  IO.popen("deno run --no-remote --allow-read=/chall/challs/generated,/chall/challs/generated.c --allow-env=SOLVER_DEBUG /submission.ts #{new_omen_name}", 
    'r+',
    # should redirect child stderr to my stdout
    :err => :out) do |line|
      got = line.gets
      line.close
  end 

  puts got
  puts got.to_i == want

  IO.popen("/chall/challs/#{new_omen_name}", 'w+', :err => :out) do |result|
    result.puts got
    puts result.gets
    puts did_get = result.gets.strip
    result.close
    unless "cool :)" == did_get 
      puts result.puts
      puts "got a wrong answer"
      exit 1
    end
  end
end

puts ENV['FLAG'] || "no flag set in environment"
