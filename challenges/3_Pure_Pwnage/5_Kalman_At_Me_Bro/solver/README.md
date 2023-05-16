# kalman-at-me-bro

A kalman filter with a weird linked list vuln

# Solver explanation

```
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

Note: If we freed the last chunk, it would be checked against all the t-cache chunks and the program would abort

5: Malloc until t-cache is empty and we are ready to allocate from fastbins (again)
    TC[0]:
    FB[4]: 4 <-> 5 <-> 6 <-> 7
    
    MM[7]: (BACK) 3 <-> 2 <-> 1 <-> 0 <-> 10 <-> 9 <-> 8 <-> 0 <-> NULL (FRONT)

6: Alloc a single chunk which has to be serviced from the fastbin (since t-cache is empty). This will move the three remaining chunks from the fastbins to the t-cache (again)
    TC[3]: 5 <-> 6 <-> 7
    FB[0]: 
    
    MM[8]: (BACK) 4 <-> 3 <-> 2 <-> 1 <-> 0 <-> 10 <-> 9 <-> 8 <-> 0 <-> NULL (FRONT)

7: Free until t-cache is full
    TC[7]: 1 <-> 2 <-> 3 <-> 4 <-> 5 <-> 6 <-> 7
    FB[0]: 
    
    MM[4]: (BACK) 0 <-> 10 <-> 9 <-> 8 <-> 0 <-> NULL (FRONT)

8: Now when we free, we'll free into the fastbins. And since we now have chunks in between the chunk we'd like to double free, we can perform the double free
    TC[7]: 1 <-> 2 <-> 3 <-> 4 <-> 5 <-> 6 <-> 7
    FB[0]: 0 <-> 8 <-> 9 <-> 10 <-> 0
    
    MM[0]: (BACK) NULL <-> NULL (FRONT)

Note: This also restores our list to a state where the FRONT and BACK pointer are both null. Meaning from here on out, our measurement list is no longer corrupted.
```
