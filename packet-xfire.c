/***************************************************
 *     Xfire Protocol dissector for Wireshark      *
 *                                                 *
 * (c) 2009 Oliver Ney <oliver@dryder.de>          *
 *                                                 *
 * Licensed under the GNU General Public License   *
 *                                                 *
 ***************************************************/

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>

#define XFIRE_PORT 25999
#define PROTOCOL_HEAD 0x55413031
#define PROTOCOL_TEST 0x75657375
#define PROTOCOL_TEST_SUCCESS 0x73756363

/* forward reference */
void proto_register_xfire();
void proto_reg_handoff_xfire(void);
static guint32 xfire_get_attribute_type_len(guint8 type, tvbuff_t *tvb, int content_offset);
static guint32 xfire_get_attribute_len_ss(tvbuff_t *tvb, int attribute_offset);
static guint32 xfire_get_attribute_len_bs(tvbuff_t *tvb, int attribute_offset);
static gchar *xfire_get_attribute_name(tvbuff_t *tvb, int *offset);
static void xfire_show_attribute(proto_tree *top_tree, tvbuff_t *tvb, int *offset, gboolean byte_type);
static void xfire_show_attribute_content(proto_tree *attribute_tree, tvbuff_t *tvb, int *offset, guint8 type);
static guint get_xfire_message_len(tvbuff_t *tvb, int offset);
static int dissect_xfire_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_xfire(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int proto_xfire = -1;
static dissector_handle_t xfire_handle;

static const guint16 string_packet_types[] = {
	0x0001, 0x0003, 0x0005, 0x000C, 0x000D, 0x0010, 0x0011, 0x0017, 0x0018, 0x0019, 0x0080,
	0x0081, 0x0082, 0x0083, 0x0085, 0x0086, 0x0087, 0x0088, 0x0089, 0x008A, 0x008B, 0x008F,
	0x0090, 0x0091, 0x0093, 0x0094, 0x0095, 0x009A, 0x009C, 0x0190, 0x0191, 0x0192, 0x0194
};

static const value_string packet_type_names[] = {
	{ 0x0001, "Log in" },
	{ 0x0003, "Xfire version" },
	{ 0x0010, "Collective statistics" },
	{ 0x0011, "Network info" },
	{ 0x0080, "Login Salt" },
	{ 0x0081, "Wrong username or password" },
	{ 0x0082, "Client information" },
	{ 0x0086, "Wrong client version" },
	{ 0x008D, "Client preferences" },
	{ 0x009D, "My screenshots" },
	{ 0x00AF, "New server IP" },
	{ 0x000A, "Change preferences" },
	{ 0x000D, "Heartbeat" },
	{ 0x001F, "Random statistics" },
	{ 0x0090, "Heartbeat" },
	{ 0x0004, "Game status change" },
	{ 0x0005, "Friend network request" },
	{ 0x0006, "Send friend invitation" },
	{ 0x0007, "Accept friend invitation" },
	{ 0x0008, "Reject friend invitation" },
	{ 0x0009, "Delete friend" },
	{ 0x000C, "Search for friends" },
	{ 0x000E, "Change nickname" },
	{ 0x000F, "Voice software status change" },
	{ 0x001A, "Create new custom group" },
	{ 0x001B, "Delete a custom group" },
	{ 0x001C, "Rename custom group" },
	{ 0x001D, "Add a friend into custom group" },
	{ 0x001E, "Remove a friend from custom group" },
	{ 0x0020, "Change status text" },
	{ 0x0023, "Game info" },
	{ 0x0025, "Request advanced infoview content for user" },
	{ 0x0083, "Friends list" },
	{ 0x0084, "Friends' online state changed" },
	{ 0x0087, "Friends' game status changed" },
	{ 0x0088, "Friend's friend network info" },
	{ 0x0089, "Respond to friend invite" },
	{ 0x008A, "Receive friend invitations" },
	{ 0x008B, "Friend removed" },
	{ 0x008F, "Friend search results" },
	{ 0x0093, "Friends' voice software status changed" },
	{ 0x0097, "Custom friends groups" },
	{ 0x0098, "Friend group associations" },
	{ 0x0099, "Custom group added" },
	{ 0x009A, "Friends' status text changed" },
	{ 0x00A1, "Friend's nickname changed" },
	{ 0x00AC, "Friend's screenshots info" },
	{ 0x00AD, "Friend's advanced info changed" },
	{ 0x00AE, "Friend's avatar info" },
	{ 0x00B0, "Friend's clan membership info" },
	{ 0x00B6, "Friend's videos" },
	{ 0x00B7, "The logged in user started playing an external game" },
	{ 0x0002, "IM to Server" },
	{ 0x0085, "IM from Server" },
	{ 0x00A9, "System Broadcast" },
	{ 0x0017, "Download to Server" },
	{ 0x0018, "Check again..." },
	{ 0x0190, "Peer info (self)" },
	{ 0x0191, "Peer info (other)" },
	{ 0x0192, "List of peers" },
	{ 0x0194, "File information" },
	{ 0x01C2, "New download channel" },
	{ 0x01C3, "New files on a download channel" },
	{ 0x01C4, "File checksum" },
	{ 0x009E, "My clans" },
	{ 0x009F, "Clan member list" },
	{ 0x00A0, "Clan member left a clan" },
	{ 0x00A2, "Clan member nickname changed" },
	{ 0x00A3, "Clan group order" },
	{ 0x00A5, "Clan invitation" },
	{ 0x00AA, "Clan events" },
	{ 0x00AB, "Clan event deleted" },
	{ 0x00B1, "News posted on clan page" },
	{ 0x0013, "Add a favorite server" },
	{ 0x0014, "Remove a favorite server" },
	{ 0x0015, "Request for list of servers - Friends' Favorites" },
	{ 0x0016, "Request for list of servers - All" },
	{ 0x0094, "Favorite servers" },
	{ 0x0095, "Server list - Friends' Favorites" },
	{ 0x0096, "Server list - All" },
	{ 0x0026, "Start or stop broadcast" },
	{ 0x00B3, "List of uploaded videos" },
	{ 0x00B8, "A friend started or stopped broadcast" },
	{ 0x0019, "Group Chat to Server" },
	{ 0x009B, "Chat room list for Servers tab on login" },
	{ 0x015E, "Chat room name changed, or entered for the first time" },
	{ 0x015F, "Chat room information on join" },
	{ 0x0161, "Someone joined the chat room" },
	{ 0x0162, "Someone left the chat room" },
	{ 0x0163, "Someone sent a message to the chat room" },
	{ 0x0164, "Invitation to a chat room" },
	{ 0x0165, "User's permission level changed" },
	{ 0x0166, "Send info about chat rooms" },
	{ 0x0167, "User kicked fom a chat room" },
	{ 0x0168, "Voice chat status changed" },
	{ 0x0169, "Force saved room?" },
	{ 0x016B, "Voice host info" },
	{ 0x016D, "Someone left voice chat" },
	{ 0x016F, "Someone joined voice chat" },
	{ 0x0170, "Room Information" },
	{ 0x0172, "Default permission level changed" },
	{ 0x0176, "MotD has been changed" },
	{ 0x0177, "Allow Voice Chat changed obsolete?" },
	{ 0x017F, "Voice session information" },
	{ 0x0180, "Response to chat room name availability" },
	{ 0x0181, "Chat room password changed" },
	{ 0x0182, "Chat room accessibility changed" },
	{ 0x0183, "Denied chat room invitation" },
	{ 0x0184, "Chat room silenced option changed" },
	{ 0x0185, "Chat room join/leave messages enabled or disabled" }
};

static const value_string attribute_type_names[] = {
	{ 0x01, "String" },
	{ 0x02, "4 Byte Integer" },
	{ 0x03, "User SID" },
	{ 0x04, "List" },
	{ 0x05, "Parent attribute (String style)" },
	{ 0x06, "Group Chat SID" },
	{ 0x07, "8 Byte Integer" },
	{ 0x08, "Boolean" },
	{ 0x09, "Parent attribute (Byte style)" }
};

static int hf_xfire_packet_len = -1;
static int hf_xfire_packet_type = -1;
static int hf_xfire_attribute_count = -1;
static int hf_xfire_attribute = -1;
static int hf_xfire_attribute_type = -1;
static int hf_xfire_attribute_type_string_len = -1;
static int hf_xfire_attribute_type_string_value = -1;
static int hf_xfire_attribute_type_int4_value = -1;
static int hf_xfire_attribute_type_userSID_value = -1;
static int hf_xfire_attribute_type_list = -1;
static int hf_xfire_attribute_type_list_type = -1;
static int hf_xfire_attribute_type_list_entry = -1;
static int hf_xfire_attribute_type_parent_ss = -1;
static int hf_xfire_attribute_type_groupSID_value = -1;
static int hf_xfire_attribute_type_int8_value = -1;
static int hf_xfire_attribute_type_boolean_value = -1;
static int hf_xfire_attribute_type_parent_bs = -1;

static gint ett_xfire = -1;
static gint ett_xfire_attribute = -1;
static gint ett_xfire_attribute_children = -1;
static gint ett_xfire_attribute_list = -1;
static gint ett_xfire_attribute_list_entry = -1;


static hf_register_info hf[] = {
	{ &hf_xfire_packet_len,
		{ "Packet length", "xfire.length",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_packet_type,
		{ "Packet type", "xfire.type",
		FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_count,
		{ "Attributes", "xfire.attributecount",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute,
		{ "Attribute", "",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type,
		{ "Type", "",
		FT_UINT8, BASE_HEX,
		VALS(attribute_type_names), 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_string_len,
		{ "String length", "",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_string_value,
		{ "String value", "",
		FT_STRINGZ, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_int4_value,
		{ "Integer value", "",
		FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_userSID_value,
		{ "User SID", "",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_list,
		{ "List entries", "",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_list_type,
		{ "List entry type", "",
		FT_UINT8, BASE_HEX,
		VALS(attribute_type_names), 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_list_entry,
		{ "Entry", "",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_parent_ss,
		{ "Children", "",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_groupSID_value,
		{ "Group Chat SID", "",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_int8_value,
		{ "Integer value", "",
		FT_UINT64, BASE_HEX_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_boolean_value,
		{ "Boolean value", "",
		FT_BOOLEAN, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_xfire_attribute_type_parent_bs,
		{ "Children", "",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	}
};

/* Setup protocol subtree array */
static gint *ett[] = {
	&ett_xfire,
	&ett_xfire_attribute,
	&ett_xfire_attribute_children,
	&ett_xfire_attribute_list,
	&ett_xfire_attribute_list_entry
};


void proto_register_xfire(void)
{
	if (proto_xfire == -1) {
		proto_xfire = proto_register_protocol (
			"Xfire Protocol",	/* name */
			"Xfire",		/* short name */
			"xfire"		/* abbrev */
			);
		proto_register_field_array(proto_xfire, hf, array_length(hf));
		proto_register_subtree_array(ett, array_length(ett));
	}
}

void proto_reg_handoff_xfire(void)
{
	static gboolean initialized = FALSE;

	if (!initialized) {
		xfire_handle = new_create_dissector_handle(dissect_xfire, proto_xfire);
		dissector_add("tcp.port", XFIRE_PORT, xfire_handle);
		initialized = TRUE;
	}
}

static guint32 xfire_get_attribute_type_len(guint8 type, tvbuff_t *tvb, int content_offset)
{
	switch(type)
	{
		// String
		case 0x01:
		{
			guint16 string_len = tvb_get_letohs(tvb, content_offset);
			return (sizeof(string_len) + string_len);
		}
		// 4 byte int
		case 0x02:
			return 4;
		// User SID
		case 0x03:
			return 16;
		break;
		// List
		case 0x04:
		{
			guint8 list_type = tvb_get_guint8(tvb, content_offset);
			guint16 list_elements = tvb_get_letohs(tvb, content_offset + 1);
			guint32 list_len = 3;
			guint16 i = 0;
			content_offset += 3;
			for(; i < list_elements; i = i + 1)
			{
				guint32 element_len = xfire_get_attribute_type_len(list_type, tvb, content_offset);
				content_offset = content_offset + element_len;
				list_len = list_len + element_len;
			}
			return list_len;
		}
		// Parent attribute (string style)
		case 0x05:
		{
			guint8 i = 0;
			guint32 attr_len = 1;
			guint8 num_attrs = tvb_get_guint8(tvb, content_offset);
			content_offset += 1;
			for(; i < num_attrs; i++)
			{
				guint32 len = xfire_get_attribute_len_ss(tvb, content_offset);
				content_offset += len;
				attr_len += len;
			}
			return attr_len;
		}
		// Group Chat SID
		case 0x06:
			return 21;
		break;
		// 8 byte int
		case 0x07:
			return 8;
		break;
		// Boolean
		case 0x08:
			return 1;
		break;
		// Parent attribute (byte style)
		case 0x09:
		{
			guint8 i = 0;
			guint32 attr_len = 1;
			guint8 num_attrs = tvb_get_guint8(tvb, content_offset);
			content_offset += 1;
			for(; i < num_attrs; i++)
			{
				guint32 len = xfire_get_attribute_len_bs(tvb, content_offset);
				content_offset += len;
				attr_len += len;
			}
			return attr_len;
		}
	}

	return 0;
}

static guint32 xfire_get_attribute_len_ss(tvbuff_t *tvb, int attribute_offset)
{
	guint8 attribute_name_len;
	guint8 attribute_type;

	// Attribute Name Len
	attribute_name_len = tvb_get_guint8(tvb, attribute_offset);
	attribute_offset += 1 + attribute_name_len;

	// Attribute type
	attribute_type = tvb_get_guint8(tvb, attribute_offset);
	attribute_offset++;

	return (2 + attribute_name_len + xfire_get_attribute_type_len(attribute_type, tvb, attribute_offset));
}

static guint32 xfire_get_attribute_len_bs(tvbuff_t *tvb, int attribute_offset)
{
	guint8 attribute_type;

	// Attribute Name == 1 byte
	attribute_offset++;

	// Attribute type
	attribute_type = tvb_get_guint8(tvb, attribute_offset);
	attribute_offset++;

	return (2 + xfire_get_attribute_type_len(attribute_type, tvb, attribute_offset));
}

static gchar *xfire_get_attribute_name(tvbuff_t *tvb, int *offset)
{
	guint8 str_len = 0;
	gchar *ret = NULL;
	str_len = tvb_get_guint8(tvb, *offset);
	ret = g_malloc0(str_len + 1);
	tvb_memcpy(tvb, ret, *offset + 1, str_len);
	*offset += 1 + str_len;
	return ret;
}

static void xfire_show_attribute_content(proto_tree *attribute_tree, tvbuff_t *tvb, int *offset, guint8 type)
{
	proto_item *ti = NULL;
	guint16 i = 0;
	switch(type)
	{
		// String
		case 0x01:
		{
			// String Len
			guint16 string_len = tvb_get_letohs(tvb, *offset);
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_string_len, tvb, *offset, 2, TRUE);
			*offset += 2;
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_string_value, tvb, *offset, string_len, TRUE);
			*offset += string_len;
			return;
		}
		// 4 Byte Integer
		case 0x02:
		{
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_int4_value, tvb, *offset, 4, TRUE);
			*offset += 4;
			return;
		}
		// User SID
		case 0x03:
		{
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_userSID_value, tvb, *offset, 16, TRUE);
			*offset += 16;
			return;
		}
		// List
		case 0x04:
		{
			proto_tree *list_tree = NULL;
			guint16 list_entries = 0;
			guint8 list_type = tvb_get_guint8(tvb, *offset);

			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_list_type, tvb, *offset, 1, TRUE);
			(*offset)++;
			list_entries = tvb_get_letohs(tvb, *offset);
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_list, tvb, *offset, 2, TRUE);
			*offset += 2;
			list_tree = proto_item_add_subtree(ti, ett_xfire_attribute_list);
			for(; i < list_entries; i++)
			{
				proto_tree *entry_tree = NULL;
				guint32 entry_len = xfire_get_attribute_type_len(list_type, tvb, *offset);
				ti = proto_tree_add_item(list_tree, hf_xfire_attribute_type_list_entry, tvb, *offset, entry_len, TRUE);
				proto_item_append_text(ti, " %u", i + 1);
				entry_tree = proto_item_add_subtree(ti, ett_xfire_attribute_list_entry);
				xfire_show_attribute_content(entry_tree, tvb, offset, list_type);
			}
			return;
		}
		// Parent attribute (String style)
		case 0x05:
		{
			proto_tree *child_tree = NULL;
			guint8 num_attributes = tvb_get_guint8(tvb, *offset);
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_parent_ss, tvb, *offset, 1, TRUE);
			(*offset)++;
			child_tree = proto_item_add_subtree(ti, ett_xfire_attribute_children);
			for(; i < num_attributes; i++)
				xfire_show_attribute(child_tree, tvb, offset, FALSE);
			return;
		}
		// Group Chat SID
		case 0x06:
		{
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_groupSID_value, tvb, *offset, 21, TRUE);
			*offset += 21;
			return;
		}
		// 8 Byte Integer
		case 0x07:
		{
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_int8_value, tvb, *offset, 8, TRUE);
			*offset += 8;
			return;
		}
		// Boolean
		case 0x08:
			{
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_boolean_value, tvb, *offset, 1, TRUE);
			(*offset)++;
			return;
		}
		break;
		// Parent attribute (Byte style)
		case 0x09:
		{
			proto_tree *child_tree = NULL;
			guint8 num_attributes = tvb_get_guint8(tvb, *offset);
			ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type_parent_bs, tvb, *offset, 1, TRUE);
			(*offset)++;
			child_tree = proto_item_add_subtree(ti, ett_xfire_attribute_children);
			for(; i < num_attributes; i++)
				xfire_show_attribute(child_tree, tvb, offset, TRUE);
			return;
		}
	}
}

static void xfire_show_attribute(proto_tree *top_tree, tvbuff_t *tvb, int *offset, gboolean byte_type)
{
	proto_tree *attribute_tree = NULL;
	guint32 attribute_len = 0;
	guint8 attribute_type = 0;
	proto_item *ti = NULL;

	// Attribute Main Item (with name)
	if(!byte_type)
	{
		gchar *attribute_name = NULL;
		int new_offset = 0;

		attribute_len = xfire_get_attribute_len_ss(tvb, *offset);

		new_offset = *offset;
		attribute_name = xfire_get_attribute_name(tvb, &new_offset);

		ti = proto_tree_add_item(top_tree, hf_xfire_attribute, tvb, *offset, attribute_len, FALSE);
		proto_item_append_text(ti, " '%s'", attribute_name);

		g_free(attribute_name);
		*offset = new_offset;
	}
	else
	{
		guint8 attribute_id = 0;

		attribute_len = xfire_get_attribute_len_bs(tvb, *offset);

		attribute_id = tvb_get_guint8(tvb, *offset);

		ti = proto_tree_add_item(top_tree, hf_xfire_attribute, tvb, *offset, attribute_len, FALSE);
		proto_item_append_text(ti, " 0x%X", attribute_id);

		(*offset)++;
	}

	attribute_tree = proto_item_add_subtree(ti, ett_xfire_attribute);

	// Attribute type
	attribute_type = tvb_get_guint8(tvb, *offset);

	ti = proto_tree_add_item(attribute_tree, hf_xfire_attribute_type, tvb, *offset, 1, FALSE);
	(*offset)++;

	xfire_show_attribute_content(attribute_tree, tvb, offset, attribute_type);
}

static int dissect_xfire(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	int tvbLen;
	int len;

	tvbLen = tvb_reported_length_remaining(tvb, offset);
	if(tvbLen < 4)
	{
		pinfo->desegment_offset = offset;
		pinfo->desegment_len = 4 - tvbLen;
		return -1;
	}

	while(tvbLen > 0)
	{
		if(tvbLen < 4)
		{
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = 4 - tvbLen;
			return -1;
		}

		len = get_xfire_message_len(tvb, offset);
		if(tvbLen < len)
		{
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = len - tvbLen;
			return -1;
		}

		offset += dissect_xfire_message(tvb, pinfo, tree, offset);

		tvbLen = tvb_reported_length_remaining(tvb, offset);
	}

	return offset;
}

static guint get_xfire_message_len(tvbuff_t *tvb, int offset)
{
	guint32 special_check = tvb_get_ntohl(tvb, offset);
	if(special_check == PROTOCOL_HEAD)
		return 4;
	else if(special_check == PROTOCOL_TEST)
		return 4;
	else if(special_check == PROTOCOL_TEST_SUCCESS)
		return 7;
	else
		return (guint)tvb_get_letohs(tvb, offset);
}

static int dissect_xfire_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	guint16 packet_len;
	guint32 special_check = tvb_get_ntohl(tvb, offset);
	guint16 packet_type = tvb_get_letohs(tvb, offset + 2);

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Xfire");
	}
	/* Clear out stuff in the info column */
	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_clear(pinfo->cinfo,COL_INFO);
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if(special_check == PROTOCOL_HEAD)
		{
			col_add_fstr(pinfo->cinfo, COL_INFO, "\"UA01\" Connection initiation");
		}
		else if(special_check == PROTOCOL_TEST)
		{
			col_add_fstr(pinfo->cinfo, COL_INFO, "\"test\" Connection test");
		}
		else if(special_check == PROTOCOL_TEST_SUCCESS)
		{
			col_add_fstr(pinfo->cinfo, COL_INFO, "\"success\" Connection test successful");
		}
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "Type 0x%.4X (%u): %s", packet_type, packet_type, val_to_str(packet_type, packet_type_names, "Unknown"));
	}
	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *xfire_tree = NULL;
		guint8 attribute_count = 0;
		gboolean byte_type = TRUE;
		guint pos = 0;
		guint8 i = 0;

		if(special_check == PROTOCOL_HEAD)
		{
			ti = proto_tree_add_item(tree, proto_xfire, tvb, offset, 4, FALSE);
			return 4;
		}
		else if(special_check == PROTOCOL_TEST)
		{
			ti = proto_tree_add_item(tree, proto_xfire, tvb, offset, 4, FALSE);
			return 4;
		}
		else if(special_check == PROTOCOL_TEST_SUCCESS)
		{
			ti = proto_tree_add_item(tree, proto_xfire, tvb, offset, 7, FALSE);
			return 7;
		}

		packet_len = tvb_get_letohs(tvb, offset);
		ti = proto_tree_add_item(tree, proto_xfire, tvb, offset, packet_len, FALSE);

		xfire_tree = proto_item_add_subtree(ti, ett_xfire);

		// Packet Length
		ti = proto_tree_add_item(xfire_tree, hf_xfire_packet_len, tvb, offset, 2, TRUE);
		proto_item_append_text(ti, " bytes");
		offset += 2;

		// Packet Type
		ti = proto_tree_add_item(xfire_tree, hf_xfire_packet_type, tvb, offset, 2, TRUE);
		//proto_item_append_text(ti, " bytes");
		offset += 2;

		// Attribute count
		ti = proto_tree_add_item(xfire_tree, hf_xfire_attribute_count, tvb, offset, 1, FALSE);
		attribute_count = tvb_get_guint8(tvb, offset);
		offset += 1;

		for(; pos < sizeof(string_packet_types); pos++)
		{
			if(string_packet_types[pos] == packet_type)
			{
				byte_type = FALSE;
				break;
			}
		}

		for(; i < attribute_count; i++)
			xfire_show_attribute(xfire_tree, tvb, &offset, byte_type);
	}

	return packet_len;
}
