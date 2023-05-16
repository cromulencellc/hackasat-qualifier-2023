require 'digest'
require 'fileutils'
require 'json'
require 'set'

UINT32_MAX = 0xffffffff

MAJORS = %w{ fool magician priestess empress emperor hierophant
  lovers chariot strength hermit wheel-of-fortune justice chillen death
  temperance devil tower star moon sun judgement world }

SUITS = %w{ wands cups swords pentacles }
MINORS = %w{ ace two three four five six seven eight nine ten page knight queen king }

CARDS = MINORS.product(SUITS).map{|c| c.join("-of-")} + MAJORS

p CARDS

hints = Hash.new

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


FileUtils.rm_rf "as-below"
FileUtils.mkdir "as-below"

CARDS.each do |card|
  dest = File.join __dir__, 'src', 'quick_maths.c'

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
      operation = %i{+ - * /}.sample
      operand = num_in_range(operation)

      result = run.send operation, operand

      # next here loops again
      next if result >= UINT32_MAX
      next if result <= 0

      stmt = "run = run #{operation} #{operand};"
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


  size = `wc -c build/ominous_etude.wasm`.split[0].to_i
  digest = `sha256sum build/ominous_etude.wasm`.split[0]

  FileUtils.mv 'build/ominous_etude.wasm', "as-below/#{card}"

  hints[card] = {
    'sha256' => digest,
    'size' => size,
    'answer' => want.to_s
  }

end

File.open('hints.json', 'w') do |h|
  h.write JSON.dump(hints)
end

`tar jfc as-below.tar.bz2 as-below`
