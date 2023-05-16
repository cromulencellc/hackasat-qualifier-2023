// deno-lint-ignore-file no-var no-explicit-any
const dec = new TextDecoder()
const enc = new TextEncoder()

let debug: (_jawn: any) => void

if (await Deno.permissions.query({name: "env", variable: "SOLVER_DEBUG"}) && 
  Deno.env.get('SOLVER_DEBUG')) {
   debug = (jawn: any) => {
    Deno.stderr.writeSync(enc.encode(Deno.inspect(jawn) + "\n"))
  }
} else {
  debug = (_jawn: any) => {}
}

function fail(mesg: string, addl?: any):never  {
  if (addl) debug(addl)
  console.log(mesg)
  Deno.exit(1)
}

function reverse_operation(run: number, operator: string, operand: number): number {
  switch (operator) {
    case "+":
      return run - operand
    case "-": 
      return run + operand
    case "/":
      return run * operand
    case "*":
      return run / operand
    default:
      fail(`couldn't invert operator ${operator}`)
  }
}

function findAnswer(_binary: Uint8Array, source: Uint8Array): number {
  const lines = dec.decode(source).split("\n")

  const senil = lines.reverse()

  // find the expected result
  const return_finder = /run == (\d+)/
  
  const result_idx = senil.findIndex(val => return_finder.test(val))
  if (-1 == result_idx) fail("couldn't find expected result", senil) 

  const expected_m = return_finder.exec(senil[result_idx])
  if (null == expected_m) fail("couldn't match expected result")

  const expected = parseInt(expected_m[1])
  var run = expected

  const call_finder = /^bool/
  const operation_finder = /run = run (.) (\d+);/
  // loop through lines undoing operations
  for(let i = result_idx + 1; i < senil.length; i++) {
    const l = senil[i]
    if (call_finder.test(l)) break;

    const parsed = operation_finder.exec(l)
    if (null == parsed) fail(`couldn't parse ${l}`)
    
    const operator = parsed[1]
    const operand = parseInt(parsed[2])

    run = Math.floor(reverse_operation(run, operator, operand))
    debug(run)
  }

  // there's your answer
  return run
}

const chall_name = Deno.args[0] || "generated-9"
const bin = Deno.readFileSync(`/chall/challs/${chall_name}`)
const src = Deno.readFileSync(`/chall/challs/${chall_name}.c`)

const answer = findAnswer(bin, src)

console.log(answer)
