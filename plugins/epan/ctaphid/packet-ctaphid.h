#include "config.h"
#include <epan/packet.h>

#define IF_CLASS_HID 0x03

#define CTAPHID_PACKET_TYPE_INIT 0x80
#define CTAPHID_PACKET_TYPE_CONT 0x00

#define CTAPHID_CMD_PING        0x01
#define CTAPHID_CMD_MSG         0x03
#define CTAPHID_CMD_LOCK        0x04
#define CTAPHID_CMD_INIT        0x06
#define CTAPHID_CMD_WINK        0x08
#define CTAPHID_CMD_CBOR        0x10
#define CTAPHID_CMD_CANCEL      0x11
#define CTAPHID_CMD_KEEPALIVE   0x3B
#define CTAPHID_CMD_ERROR       0x3F

#define CTAPHID_INIT_WINK_FLAG  0x01
#define CTAPHID_INIT_CBOR_FLAG  0x04
#define CTAPHID_INIT_NMSG_FLAG  0x08

#define CTAP_AUTHENTICATOR_MAKE_CREDENTIAL          0x01
#define CTAP_AUTHENTICATOR_GET_ASSERTION            0x02
#define CTAP_AUTHENTICATOR_GET_INFO                 0x04
#define CTAP_AUTHENTICATOR_CLIENT_PIN               0x06
#define CTAP_AUTHENTICATOR_RESET                    0x07
#define CTAP_AUTHENTICATOR_GET_NEXT_ASSERTION       0x08
#define CTAP_AUTHENTICATOR_BIO_ENROLLMENT           0x09
#define CTAP_AUTHENTICATOR_CREDENTIAL_MANAGEMENT    0x0A
#define CTAP_AUTHENTICATOR_SELECTION                0x0B
#define CTAP_AUTHENTICATOR_LARGE_BLOBS              0x0C
#define CTAP_AUTHENTICATOR_CONFIG                   0x0D

/* Count indices; meant to be used with CTAPHID_stats.init_count */
#define COUNT_CBOR  0
#define COUNT_MSG   1
#define COUNT_PING  2

typedef struct {
    /* Current CTAPHID packet type */
    guint8 type;
    /* Current CTAPHID command */
    guint8 cmd;
    /* Current CTAPHID byte count */
    guint16 bcnt;   
    /* Init packet count for different commands */
    gint init_count[3];
} CTAPHID_stats;
