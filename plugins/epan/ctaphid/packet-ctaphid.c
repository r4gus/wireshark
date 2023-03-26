#include "packet-ctaphid.h"

static int proto_CTAPHID = -1;
static dissector_handle_t CTAPHID_handle;

static int hf_CTAPHID_cid = -1;
static int hf_CTAPHID_cmd = -1;
static int hf_CTAPHID_bcnt = -1;
static int hf_CTAPHID_seq = -1;
static int hf_CTAPHID_data = -1;
static int hf_CTAPHID_init_nonce = -1;
static int hf_CTAPHID_init_cid = -1;
static int hf_CTAPHID_init_prot = -1;
static int hf_CTAPHID_init_majv = -1;
static int hf_CTAPHID_init_minv = -1;
static int hf_CTAPHID_init_buildv = -1;
static int hf_CTAPHID_init_capabilities_flags = -1;
static int hf_CTAPHID_init_capabilities_wink_flag = -1;
static int hf_CTAPHID_init_capabilities_cbor_flag = -1;
static int hf_CTAPHID_init_capabilities_nmsg_flag = -1;
static int hf_CTAP_cmd = -1;
static int hf_CTAP_status = -1;

static gint ett_CTAPHID = -1;

static const value_string packettypenames[] = {
    { 0x80, "INIT" },
    { 0x00, "CONT" },
};

static const value_string cmdnames[] = {
    { 0x01, "PING" },
    { 0x03, "MSG" },
    { 0x04, "LOCK" },
    { 0x06, "INIT" },
    { 0x08, "WINK" },
    { 0x10, "CBOR" },
    { 0x11, "CANCEL" },
    { 0x3B, "KEEPALIVE" },
    { 0x3F, "ERROR" },
};

static const value_string ctapcmdnames[] = {
    { 0x01, "authenticatorMakeCredential" },
    { 0x02, "authenticatorGetAssertion" },
    { 0x04, "authenticatorGetInfo" },
    { 0x06, "authenticatorClientPin" },
    { 0x07, "authenticatorReset" },
    { 0x08, "authenticatorGetNextAssertion" },
    { 0x09, "authenticatorBioEnrollment" },
    { 0x0A, "authenticatorCredentialManagement" },
    { 0x0B, "authenticatorSelection" },
    { 0x0C, "authenticatorLargeBlobs" },
    { 0x0D, "authenticatorConfig" },
};

static const value_string ctapstatusnames[] = {
    { 0x00, "CTAP2_OK" },
    { 0x01, "CTAP1_ERR_INVALID_COMMAND" },
    { 0x02, "CTAP1_ERR_INVALID_PARAMETER" },
    { 0x03, "CTAP1_ERR_INVALID_LENGTH" },
    { 0x04, "CTAP1_ERR_INVALID_SEQ" },
    { 0x05, "CTAP1_ERR_TIMEOUT" },
    { 0x06, "CTAP1_ERR_CHANNEL_BUSY" },
    { 0x0A, "CTAP1_ERR_LOCK_REQUIRED" },
    { 0x0B, "CTAP1_ERR_INVALID_CHANNEL" },
    { 0x11, "CTAP2_ERR_CBOR_UNEXPECTED_TYPE" },
    { 0x12, "CTAP2_ERR_INVALID_CBOR" },
    { 0x14, "CTAP2_ERR_MISSING_PARAMETER" },
    { 0x15, "CTAP2_ERR_LIMIT_EXCEEDED" },
    { 0x17, "CTAP2_ERR_FP_DATABASE_FULL" },
    { 0x18, "CTAP2_ERR_LARGE_BLOB_STORAGE_FULL" },
    { 0x19, "CTAP2_ERR_CREDENTIAL_EXCLUDED" },
    { 0x21, "CTAP2_ERR_PROCESSING" },
    { 0x22, "CTAP2_ERR_INVALID_CREDENTIAL" },
    { 0x23, "CTAP2_ERR_USER_ACTION_PENDING" },
    { 0x24, "CTAP2_ERR_OPERATION_PENDING" },
    { 0x25, "CTAP2_ERR_NO_OPERATIONS" },
    { 0x26, "CTAP2_ERR_UNSUPPORTED_ALGORITHM" },
    { 0x27, "CTAP2_ERR_OPERATION_DENIED" },
    { 0x28, "CTAP2_ERR_KEY_STORE_FULL" },
    { 0x2B, "CTAP2_ERR_UNSUPPORTED_OPTION" },
    { 0x2C, "CTAP2_ERR_INVALID_OPTION" },
    { 0x2D, "CTAP2_ERR_KEEPALIVE_CANCEL" },
    { 0x2E, "CTAP2_ERR_NO_CREDENTIALS" },
    { 0x2F, "CTAP2_ERR_USER_ACTION_TIMEOUT" },
    { 0x30, "CTAP2_ERR_NOT_ALLOWED" },
    { 0x31, "CTAP2_ERR_PIN_INVALID" },
    { 0x32, "CTAP2_ERR_PIN_BLOCKED" },
    { 0x33, "CTAP2_ERR_PIN_AUTH_INVALID" },
    { 0x34, "CTAP2_ERR_PIN_AUTH_BLOCKED" },
    { 0x35, "CTAP2_ERR_PIN_NOT_SET" },
    { 0x36, "CTAP2_ERR_PUAT_REQUIRED" },
    { 0x37, "CTAP2_ERR_PIN_POLICY_VIOLATION" },
    { 0x38, "Reserved for Future Use" },
    { 0x39, "CTAP2_ERR_REQUEST_TOO_LARGE" },
    { 0x3A, "CTAP2_ERR_ACTION_TIMEOUT" },
    { 0x3B, "CTAP2_ERR_UP_REQUIRED" },
    { 0x3C, "CTAP2_ERR_UV_BLOCKED" },
    { 0x3D, "CTAP2_ERR_INTEGRITY_FAILURE" },
    { 0x3E, "CTAP2_ERR_INVALID_SUBCOMMAND" },
    { 0x3F, "CTAP2_ERR_UV_INVALID" },
    { 0x40, "CTAP2_ERR_UNAUTHORIZED_PERMISSION" },
    { 0x7F, "CTAP1_ERR_OTHER" },
};

static void
dissect_cmd_init(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, CTAPHID_stats *stats)
{
    if (stats->bcnt == 8) { // client -> authenticator
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Client -> Authenticator");

        // nonce
        proto_tree_add_item(tree, hf_CTAPHID_init_nonce, tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;
    } else if (stats->bcnt == 17) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Authenticator -> Client");

        // nonce
        proto_tree_add_item(tree, hf_CTAPHID_init_nonce, tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;

        // allocated cid
        proto_tree_add_item(tree, hf_CTAPHID_init_cid, tvb, *offset, 4, ENC_BIG_ENDIAN);
        *offset += 4;

        // CTAPHID protocol version identifier 
        proto_tree_add_item(tree, hf_CTAPHID_init_prot, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;

        // CTAPHID protocol version identifier 
        proto_tree_add_item(tree, hf_CTAPHID_init_majv, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;

        // CTAPHID protocol version identifier 
        proto_tree_add_item(tree, hf_CTAPHID_init_minv, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;

        // CTAPHID protocol version identifier 
        proto_tree_add_item(tree, hf_CTAPHID_init_buildv, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;
        
        // Capabilities
        static int* const bits[] = {
            &hf_CTAPHID_init_capabilities_wink_flag,
            &hf_CTAPHID_init_capabilities_cbor_flag,
            &hf_CTAPHID_init_capabilities_nmsg_flag,
            NULL
        };

        proto_tree_add_bitmask(tree, tvb, *offset, hf_CTAPHID_init_capabilities_flags, 
                ett_CTAPHID, bits, ENC_BIG_ENDIAN);
        *offset += 1;
    }     
}

static void
dissect_cmd_cbor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint *offset, CTAPHID_stats *stats)
{
    /* Try to guess the direction of communication based on the given stats */
    if (stats->type == CTAPHID_PACKET_TYPE_INIT && stats->init_count[COUNT_CBOR] % 2 == 1) // TODO: this is a very curde heuristic
    {
        // CTAP command byte
        proto_tree_add_item(tree, hf_CTAP_cmd, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;
    } 
    else if (stats->type == CTAPHID_PACKET_TYPE_INIT && stats->init_count[COUNT_CBOR] % 2 == 0)
    {
        // CTAP command byte
        proto_tree_add_item(tree, hf_CTAP_status, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;
    }

    if (stats->init_count[COUNT_CBOR] % 2 == 1) // TODO: this is a very curde heuristic
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Client -> Authenticator");
    } 
    else
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Authenticator -> Client");
    }

}

static int
dissect_CTAPHID(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    static CTAPHID_stats stats;
    // CTAPHID command: this will be set by an initialization packet
    //static guint8 cmd = 0xFF;
    // The byte count is also set by an init packet
    //static guint16 bcnt = 0;

    gint offset = 0;
    stats.type = tvb_get_guint8(tvb, 4) & 0x80;

    /* Info */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTAPHID");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
            val_to_str(stats.type, packettypenames, "Unknown (0x%02x)"));
    
    proto_item *ti = proto_tree_add_item(tree, proto_CTAPHID, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type: %s",
        val_to_str(stats.type, packettypenames, "Unknown (0x%02x)"));

    /* Build CTAPHID subtree */
    proto_tree *CTAPHID_tree = proto_item_add_subtree(ti, ett_CTAPHID);
    proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_cid, tvb, 0, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (stats.type == CTAPHID_PACKET_TYPE_INIT) {
        // command
        stats.cmd = tvb_get_guint8(tvb, offset) & 0x7F;
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        
        /*
         * Count the number of init packets for a specific command.
         * This can help determine if it was sent by the client or
         * authenticator.
         */
        switch (stats.cmd) {
            case CTAPHID_CMD_MSG:
                stats.init_count[COUNT_MSG] += 1;
                break;  
            case CTAPHID_CMD_CBOR:
                stats.init_count[COUNT_CBOR] += 1;
                break;
            case CTAPHID_CMD_PING:
                stats.init_count[COUNT_PING] += 1;
                break;
        };
 
        // byte count
        stats.bcnt = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_bcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else if (stats.type == CTAPHID_PACKET_TYPE_CONT) {
        // sequence number
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    } 
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Cmd: %s", val_to_str(stats.cmd, cmdnames, "Unknown (0x%02x)"));

    /* Build CTAPHID data subtree */
    proto_item *ti2 = proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_data, tvb, 
            offset, -1, ENC_BIG_ENDIAN);

    proto_tree *data_tree = proto_item_add_subtree(ti2, ett_CTAPHID);
    
    switch (stats.cmd) {
        case CTAPHID_CMD_PING:
            break;
        case CTAPHID_CMD_MSG:
            break;  
        case CTAPHID_CMD_LOCK:
            break;  
        case CTAPHID_CMD_INIT:
            dissect_cmd_init(tvb, pinfo, data_tree, &offset, &stats);    
            break;  
        case CTAPHID_CMD_WINK:
            break;  
        case CTAPHID_CMD_CBOR:
            proto_item_append_text(ti2, ", Type: %s", val_to_str(stats.cmd, cmdnames, "Unknown (0x%02x)"));
            dissect_cmd_cbor(tvb, pinfo, data_tree, &offset, &stats);    
            break;  
        case CTAPHID_CMD_CANCEL:
            break;  
        case CTAPHID_CMD_KEEPALIVE:
            break;  
        case CTAPHID_CMD_ERROR:
            break;  
    };

    return tvb_captured_length(tvb);
}

void
proto_register_CTAPHID(void)
{
    static hf_register_info hf[] = {
        { &hf_CTAPHID_cid,
            { "Channel id", "CTAPHID.cid",
              FT_UINT32, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_cmd,
            { "Command", "CTAPHID.cmd",
              FT_UINT8, BASE_HEX,
              VALS(cmdnames), 0x7f,
              NULL, HFILL }
        },
        { &hf_CTAPHID_bcnt,
            { "Byte count", "CTAPHID.bcnt",
              FT_UINT16, BASE_DEC,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_seq,
            { "Sequence number", "CTAPHID.seq",
              FT_UINT8, BASE_DEC,
              NULL, 0x7f,
              NULL, HFILL }
        },
        { &hf_CTAPHID_data,
            { "Data", "CTAPHID.data",
              FT_BYTES, BASE_NONE,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_nonce,
            { "Nonce", "CTAPHID.init.nonce",
              FT_BYTES, BASE_NONE,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_cid,
            { "Allocated cid", "CTAPHID.init.cid",
              FT_UINT32, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_prot,
            { "CTAPHID protocol version identifier", "CTAPHID.init.prot",
              FT_UINT8, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_majv,
            { "Major device version number", "CTAPHID.init.majv",
              FT_UINT8, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_minv,
            { "Minor device version number", "CTAPHID.init.minv",
              FT_UINT8, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_buildv,
            { "Build device version number", "CTAPHID.init.build",
              FT_UINT8, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_capabilities_flags,
            { "Capabilities", "CTAPHID.init.flags",
              FT_UINT8, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_capabilities_wink_flag,
            { "WINK", "CTAPHID.init.flags.wink",
              FT_BOOLEAN, 8,
              NULL, CTAPHID_INIT_WINK_FLAG,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_capabilities_cbor_flag,
            { "CBOR", "CTAPHID.init.flags.cbor",
              FT_BOOLEAN, 8,
              NULL, CTAPHID_INIT_CBOR_FLAG,
              NULL, HFILL }
        },
        { &hf_CTAPHID_init_capabilities_nmsg_flag,
            { "NMSG", "CTAPHID.init.flags.nmsg",
              FT_BOOLEAN, 8,
              NULL, CTAPHID_INIT_NMSG_FLAG,
              NULL, HFILL }
        },
        { &hf_CTAP_cmd,
            { "CTAP command byte", "CTAP.cmd",
              FT_UINT8, BASE_HEX,
              VALS(ctapcmdnames), 0x00,
              NULL, HFILL }
        },
        { &hf_CTAP_status,
            { "CTAP status code", "CTAP.status",
              FT_UINT8, BASE_HEX,
              VALS(ctapstatusnames), 0x00,
              NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_CTAPHID
    };

    proto_CTAPHID = proto_register_protocol (
        "CTAPHID Protocol", /* name        */
        "CTAPHID",          /* short_name  */
        "ctaphid"           /* filter_name */
    );

    proto_register_field_array(proto_CTAPHID, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_CTAPHID(void)
{
    CTAPHID_handle = create_dissector_handle(dissect_CTAPHID, proto_CTAPHID);
    dissector_add_uint("usb.interrupt", IF_CLASS_HID, CTAPHID_handle);
}
