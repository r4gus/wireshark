#include "config.h"
#include <epan/packet.h>
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

static int
dissect_CTAPHID(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    // CTAPHID command: this will be set by an initialization packet
    static guint8 cmd = 0xFF;
    // The byte count is also set by an init packet
    static guint16 bcnt = 0;

    gint offset = 0;
    guint8 packet_type = tvb_get_guint8(tvb, 4) & 0x80;

    /* Info */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTAPHID");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
            val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));
    
    proto_item *ti = proto_tree_add_item(tree, proto_CTAPHID, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type: %s",
        val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    /* Build CTAPHID subtree */
    proto_tree *CTAPHID_tree = proto_item_add_subtree(ti, ett_CTAPHID);
    proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_cid, tvb, 0, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (packet_type == CTAPHID_PACKET_TYPE_INIT) {
        // command
        cmd = tvb_get_guint8(tvb, offset) & 0x7F;
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
 
        // byte count
        bcnt = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_bcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else if (packet_type == CTAPHID_PACKET_TYPE_CONT) {
        // sequence number
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    } 
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Cmd: %s", val_to_str(cmd, cmdnames, "Unknown (0x%02x)"));

    /* Build CTAPHID data subtree */
    proto_item *ti2 = proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_data, tvb, 
            offset, -1, ENC_BIG_ENDIAN);

    if (cmd == CTAPHID_CMD_CBOR || cmd == CTAPHID_CMD_MSG) {
        proto_item_append_text(ti2, ", Type: %s", val_to_str(cmd, cmdnames, "Unknown (0x%02x)"));
    } else if (cmd == CTAPHID_CMD_INIT) {
        proto_tree *data_tree = proto_item_add_subtree(ti2, ett_CTAPHID);

        if (bcnt == 8) { // client -> authenticator
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Client -> Authenticator");

            // nonce
            proto_tree_add_item(data_tree, hf_CTAPHID_init_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
        } else if (bcnt == 17) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Authenticator -> Client");

            // nonce
            proto_tree_add_item(data_tree, hf_CTAPHID_init_nonce, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;

            // allocated cid
            proto_tree_add_item(data_tree, hf_CTAPHID_init_cid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            // CTAPHID protocol version identifier 
            proto_tree_add_item(data_tree, hf_CTAPHID_init_prot, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            // CTAPHID protocol version identifier 
            proto_tree_add_item(data_tree, hf_CTAPHID_init_majv, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            // CTAPHID protocol version identifier 
            proto_tree_add_item(data_tree, hf_CTAPHID_init_minv, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            // CTAPHID protocol version identifier 
            proto_tree_add_item(data_tree, hf_CTAPHID_init_buildv, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            
            // Capabilities
            static int* const bits[] = {
                &hf_CTAPHID_init_capabilities_wink_flag,
                &hf_CTAPHID_init_capabilities_cbor_flag,
                &hf_CTAPHID_init_capabilities_nmsg_flag,
                NULL
            };

            proto_tree_add_bitmask(data_tree, tvb, offset, hf_CTAPHID_init_capabilities_flags, ett_CTAPHID, bits, ENC_BIG_ENDIAN);
            offset += 1;
        }     
    }

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
