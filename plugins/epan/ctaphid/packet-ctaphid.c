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
    gint offset = 0;
    guint8 packet_type = tvb_get_guint8(tvb, 4) & 0x80;

    /* Info */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTAPHID");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Packet Type: %s",
            val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));
    
    proto_item *ti = proto_tree_add_item(tree, proto_CTAPHID, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type: %s",
        val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    /* Build CTAPHID subtree */
    proto_tree *CTAPHID_tree = proto_item_add_subtree(ti, ett_CTAPHID);
    proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_cid, tvb, 0, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (packet_type == CTAPHID_PACKET_TYPE_INIT) {
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_bcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else if (packet_type == CTAPHID_PACKET_TYPE_CONT) {
        proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    } 

    /* Build CTAPHID data subtree */
    proto_tree_add_item(CTAPHID_tree, hf_CTAPHID_data, tvb, offset, -1, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

void
proto_register_CTAPHID(void)
{
    static hf_register_info hf[] = {
        { &hf_CTAPHID_cid,
            { "Channel Id (CID)", "CTAPHID.cid",
              FT_UINT32, BASE_HEX,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_cmd,
            { "Command (CMD)", "CTAPHID.cmd",
              FT_UINT8, BASE_HEX,
              VALS(cmdnames), 0x7f,
              NULL, HFILL }
        },
        { &hf_CTAPHID_bcnt,
            { "Byte Count (BCNT)", "CTAPHID.bcnt",
              FT_UINT16, BASE_DEC,
              NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_CTAPHID_seq,
            { "Sequence Number (SEQ)", "CTAPHID.seq",
              FT_UINT8, BASE_DEC,
              NULL, 0x7f,
              NULL, HFILL }
        },
        { &hf_CTAPHID_data,
            { "Data", "CTAPHID.data",
              FT_BYTES, BASE_NONE,
              NULL, 0x00,
              NULL, HFILL }
        }
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
