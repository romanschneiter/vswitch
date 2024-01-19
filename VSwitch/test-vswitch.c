/**
 * @file test-vswitch.c
 * @brief Testcase for the 'vswitch'.  Must be linked with harness.c.
 * @author Christian Schmidhalter, Roman Schneiter
 */
#include "harness.h"

/**
 * Set to 1 to enable debug statments.
 */
#define DEBUG 1
#define TAGGED_HEADER_SIZE 16
#define UNTAGGED_HEADER_SIZE 12
#define PAYLOAD_SIZE 512

// Untagged Frame
struct UTFrame
{
    struct MacAddress src;
    struct MacAddress dst;
};

// Tagged Frame
struct TFrame
{
    struct MacAddress src;
    struct MacAddress dst;
    struct Tag
    {
        uint16_t tpid;
        uint16_t tci;
    } tag;
};

/*
Generates an untagged and a tagged frame for testing
*/
void generate_frames(uint8_t *TFrame, uint8_t *UTFrame)
{
    // Tagged:   src mac + dst mac (12 byte) + tag (4byte) + payload (n byte)
    // Untagged: src mac + dst mac (12 byte)               + payload (n byte)

    // Sample source and destintion mac
    struct MacAddress srcMac = {{0x00, 0x11, 0x22, 0xAA, 0xBB, 0xCC}};
    struct MacAddress dstMac = {{0x00, 0xAA, 0x88, 0x66, 0x44, 0x22}};

    // Build tagged and untagged header
    struct UTFrame UTHeader;
    struct TFrame THeader;

    // Add Mac source and destination mac to header
    for (int i = 0; i < 6; i++) 
    {
        UTHeader.src.mac[i] = srcMac.mac[i];
        UTHeader.dst.mac[i] = dstMac.mac[i];
        THeader.src.mac[i] = srcMac.mac[i];
        THeader.dst.mac[i] = dstMac.mac[i];
    }
    THeader.tag.tpid = htons(0x8100); //Tag Protocol Identifier: fix value 8100
    THeader.tag.tci = htons(0x1); // Tag Control Information

    // Add Header to frame
    for (int i = 0; i < sizeof(struct TFrame); i++) 
    {
        TFrame[i] = *((uint8_t*)&THeader + i);

        if(i < sizeof(struct UTFrame))
        {
        UTFrame[i] = *((uint8_t*)&UTHeader + i);
        }
    }

    // Populate random payload
    uint8_t payload[PAYLOAD_SIZE];
    for (unsigned int i = 0; i < PAYLOAD_SIZE; i++)
    {
        payload[i] = random();
    }

    // Add payload to frame
    for (unsigned int i = 0; i < PAYLOAD_SIZE; i++)
    {
        TFrame[i + TAGGED_HEADER_SIZE] = payload[i]; 
        UTFrame[i + UNTAGGED_HEADER_SIZE] = payload[i];
    }
}


/*
Removal of tag.
Sends from tagged source. Expects untagged frame.
*/
static int remove_tag(const char *prog)
{

    uint8_t TFrame[TAGGED_HEADER_SIZE + PAYLOAD_SIZE]; 
    uint8_t UTFrame[UNTAGGED_HEADER_SIZE + PAYLOAD_SIZE];
    generate_frames(TFrame, UTFrame);
   
    int send_tagged_frame()
    {
        tsend(1, TFrame, sizeof(TFrame));
        return 0;
    };

    int expect_untagged_frame()
    {
        uint64_t ifc = (1 << 1);
        return trecv(
            1,
            &expect_multicast,
            &ifc,
            UTFrame,
            sizeof(UTFrame),
            UINT16_MAX);
    };

    char *argv[] = {(char *)prog, "eth0[T:1]", "eth1[U:1]", "eth2[U:2]", "eth3[U:3]", NULL};

    struct Command cmd[] = {
        {"send tagged frame", &send_tagged_frame},
        {"check untagged frame", &expect_untagged_frame},
        {"end", &expect_silence},
        {NULL}};

    return meta(cmd, (sizeof(argv) / sizeof(char *)) - 1, argv);

}

/*
Adding a tag.
Sends from untagged source. Expects tagged frame.
*/
static int add_tag(const char *prog)
{
    uint8_t TFrame[TAGGED_HEADER_SIZE + PAYLOAD_SIZE];
    uint8_t UTFrame[UNTAGGED_HEADER_SIZE + PAYLOAD_SIZE];
    generate_frames(TFrame, UTFrame);

    int send_untagged_frame()
    {
        tsend(1, UTFrame, sizeof(UTFrame));
        return 0;
    };

    int expect_tagged_frame()
    {
        uint64_t ifc = (1 << 1);
        return trecv(
            1,
            &expect_multicast,
            &ifc,
            TFrame,
            sizeof(TFrame),
            UINT16_MAX);
    };

    char *argv[] = {(char *)prog, "eth0[U:1]", "eth1[T:1]", "eth2[U:2]", "eth3[U:3]", NULL};

    struct Command cmd[] = {
        {"send untagged frame", &send_untagged_frame},
        {"check tagged frame", &expect_tagged_frame},
        {"end", &expect_silence},
        {NULL}};

    return meta(cmd, (sizeof(argv) / sizeof(char *)) - 1, argv);
}

/*
Incorrect forwarding.
Sends tagged frame from untagged source. Expects silence.
*/
static int send_incorrect(const char *prog)
{

    uint8_t TFrame[TAGGED_HEADER_SIZE + PAYLOAD_SIZE];
    uint8_t UTFrame[UNTAGGED_HEADER_SIZE + PAYLOAD_SIZE];
    generate_frames(TFrame, UTFrame);

    int send_tagged_frame()
    {
        tsend(1, TFrame, sizeof(TFrame));
        return 0;
    };

    char *argv[] = {(char *)prog, "eth0[U:1]", "eth1[T:1]", "eth2[U:2]", "eth3[U:3]", NULL};

    struct Command cmd[] = {
        {"send tagged frame", &send_tagged_frame},
        {"expect silence, end", &expect_silence},
        {NULL}};

    return meta(cmd, (sizeof(argv) / sizeof(char *)) - 1, argv);
}

/**
 * Call with path to the switch program to test.
 */
int main(int argc,
         char **argv)
{
    unsigned int grade = 0;
    unsigned int possible = 0;
    struct Test
    {
        const char *name;
        int (*fun)(const char *arg);
    } tests[] = {
         {"Remove tag from frame", &remove_tag}, // bug1
         {"Add tag to frame", &add_tag}, // bug2
         {"Send tagged frame from untagged source", &send_incorrect}, // bug3
         {NULL, NULL}
    };

    if (argc != 2)
    {
        fprintf(stderr,
                "Call with VSWITCH to test as 1st argument!\n");
        return 1;
    }
    for (unsigned int i = 0; NULL != tests[i].fun; i++)
    {
        if (0 == tests[i].fun(argv[1]))
            grade++;
        else
            fprintf(stdout,
                    "Failed test `%s'\n",
                    tests[i].name);
        possible++;
    }
    fprintf(stdout,
            "Final grade: %u/%u\n",
            grade,
            possible);
    
    return grade != possible ? 1 : 0;
}