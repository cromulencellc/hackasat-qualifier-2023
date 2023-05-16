// deno-lint-ignore-file prefer-const
import iced from "npm:iced-x86@1.18.0"
import elfinfo from "npm:elfinfo@0.4.0-beta"
import predicates from "npm:@tool-belt/type-predicates@1.2.2"

let debug: (_jawn: any) => void

if (await Deno.permissions.query({name: "env", variable: "SOLVER_DEBUG"}) && 
  Deno.env.get('SOLVER_DEBUG')) {
    const enc = new TextEncoder()

    debug = (jawn: any) => {
      Deno.stderr.writeSync(enc.encode(Deno.inspect(jawn) + "\n"))
    }
} else {
  debug = (_jawn: any) => {}
}

let file_data = await Deno.readFile("/chall/challs/generated")

// template stops here?

let info = await elfinfo.open(file_data, 
  { readSymbolData: true })
let elf = info.elf

predicates.assertIsDefined(elf)

let quick_maths_sym = elfinfo.getSymbolByName(elf, "quick_maths")

predicates.assertIsDefined(quick_maths_sym)
predicates.assertIsUint8Array(quick_maths_sym.data)

let decoder = new iced.Decoder(64, quick_maths_sym.data,
  iced.DecoderOptions.None)

let formatter = new iced.Formatter(iced.FormatterSyntax.Nasm)

let quick_maths_instructions: iced.Instruction[] = decoder.decodeAll()
let info_factory = new iced.InstructionInfoFactory()

let first_rip = quick_maths_instructions[0].ip + BigInt(quick_maths_sym.value)
debug(first_rip)

class Operation {
  operand: number
  operation: iced.Mnemonic

  constructor(_operand: number, _operation: iced.Mnemonic) {
    this.operand = _operand
    this.operation = _operation
  }

  rollback(running: number) {
    switch (this.operation) {
      case iced.Mnemonic.Ucomisd: return this.operand
      case iced.Mnemonic.Subsd: return this.operand + running
      case iced.Mnemonic.Divsd: return this.operand * running
      case iced.Mnemonic.Addsd: return running - this.operand
      default:
        debug(`can't handle ${iced.Mnemonic[this.operation]}`)
        Deno.exit(1)
    }
  }

  _replaceables = [
    iced.Mnemonic.Subsd,
    iced.Mnemonic.Divsd,
    iced.Mnemonic.Addsd
  ]

  replace_operation(maybe_operation: iced.Mnemonic) {
    if (this.operation != iced.Mnemonic.Movsd) return
    if (! this._replaceables.includes(maybe_operation)) return
    this.operation = maybe_operation
  }
}

let instructions: Operation[] = []

quick_maths_instructions.forEach((ins: iced.Instruction) => {
  let info = info_factory.info(ins)
  let addr = ins.ip + first_rip
  let addr_s = ("000000000000000" + addr.toString(16)).substr(-16).toUpperCase()
  let disas_s = formatter.format(ins)
  debug(`${addr_s} ${disas_s}`)
  let regs = info.usedRegisters()
  let reg_names = regs.map(r => iced.Register[r.register])
  let is_movsd = (iced.Mnemonic.Movsd == ins.mnemonic)
  let is_ucomisd = (iced.Mnemonic.Ucomisd == ins.mnemonic)
  let is_read = (is_movsd || is_ucomisd) && (iced.OpAccess.Read == info.op1Access)
  let is_interesting_movsd = is_movsd && is_read && (reg_names.length == 1)

  if (is_interesting_movsd || is_ucomisd) {
    debug(iced.OpKind[ins.op1Kind])
    debug(reg_names)
    let num_addr = first_rip + ins.memoryDisplacement
    debug(num_addr.toString(16))
    let file_addr = elfinfo.virtualAddressToFileOffset(elf, num_addr)
    debug(file_addr)
    let buf = new Float64Array(file_data.buffer, file_addr, 8)
    let operand = buf[0]
    debug(operand)

    instructions.push(new Operation(operand, ins.mnemonic))
  } else if (instructions.length > 0) {
    let last_ins = instructions[instructions.length - 1]
    last_ins.replace_operation(ins.mnemonic)
  }
})

debug(instructions)

console.log(instructions.
  reverse().
  reduce(((run: number, ins: Operation) => ins.rollback(run)), -1))