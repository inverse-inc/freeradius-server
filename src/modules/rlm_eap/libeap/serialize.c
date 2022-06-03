/*
 * cache.c Caching of EAP state
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2022  The FreeRADIUS server project
 * Copyright 2022  Akamai/Inverse
 */

#include "eap_tls.h"
int serialize_fixed(UNUSED void *instance, REQUEST *fake, eap_handler_t *handler, size_t len)
{
	VALUE_PAIR *vp;

	vp = fr_pair_afrom_num(fake->reply, PW_EAP_SERIALIZED_OPAQUE, 0);
	fr_pair_value_memcpy(vp, handler->opaque, len);
	fr_pair_add(&fake->reply->vps, vp);

	return 1;
}

int deserialize_fixed(UNUSED void *instance, REQUEST *fake, eap_handler_t *handler, size_t len)
{
	VALUE_PAIR *vp;
	uint8_t * p;

	vp = fr_pair_find_by_num(fake->reply->vps, PW_EAP_SERIALIZED_OPAQUE, 0, TAG_ANY);
	if (!vp) return 0;
    if ( vp->vp_length != len) return 0;
	p = talloc_memdup(handler, vp->vp_octets, vp->vp_length);
	if (!p) return 0;
	handler->opaque = p;

	return 1;
}

static int serialize_record_t(json_object *obj, const char* name, record_t * record)
{
	json_object *val;
	char data[MAX_RECORD_SIZE * 2];

	if (record->used == 0) return 1;

	fr_bin2hex(data, record->data, record->used);
	MEM(val = json_object_new_string_len(data, record->used * 2));
	json_object_object_add(obj, name, val);
	return 1;
}

int serialize_tls_session(UNUSED REQUEST *request, UNUSED void *instance, UNUSED REQUEST *fake, json_object *obj, tls_session_t *ssn)
{
	json_object *val;

#define SET_BOOL(n) do {\
	MEM(val = json_object_new_boolean((ssn->n)));\
	json_object_object_add(obj, #n, val);\
} while(0)

#define SET_INT(n) do {\
	MEM(val = json_object_new_int64((ssn->n)));\
	json_object_object_add(obj, #n, val);\
} while(0)

	serialize_record_t(obj, "clean_in", &ssn->clean_in);
	serialize_record_t(obj, "clean_out", &ssn->clean_out);
	serialize_record_t(obj, "dirty_in", &ssn->dirty_in);
	serialize_record_t(obj, "dirty_out", &ssn->dirty_out);
	SET_BOOL(invalid_hb_used);
	SET_BOOL(connected);
	SET_BOOL(is_init_finished);
	SET_BOOL(client_cert_ok);
	SET_BOOL(authentication_success);
	SET_BOOL(quick_session_tickets);
	SET_BOOL(fragment);
	SET_BOOL(length_flag);
	SET_BOOL(allow_session_resumption);
	SET_BOOL(session_not_resumed);

	SET_INT(mtu);
	SET_INT(tls_msg_len);
	SET_INT(peap_flag);
#undef SET_BOOL
#undef SET_INT
	return 1;
}

int deserialize_tls_session(REQUEST *request, UNUSED void *instance, UNUSED REQUEST *fake, json_object *obj, tls_session_t *ssn)
{
	json_object *val;

#define SET_INT(f) do {\
	uint64_t num;\
	if (!json_object_object_get_ex(obj, #f, &val)) {\
		RERROR("Cannot find " #f);\
		return 0;\
	}\
	num = json_object_get_int64(val);\
	ssn->f = num;\
	RDEBUG("Setting " #f "with %ld ", num);\
} while(0)

#define SET_BOOL(f) do {\
	if (!json_object_object_get_ex(obj, #f, &val)) {\
		RERROR("Cannot find " #f);\
		return 0;\
	}\
	\
	ssn->f = json_object_get_boolean(val);\
} while(0)

	SET_BOOL(invalid_hb_used);
	SET_BOOL(connected);
	SET_BOOL(is_init_finished);
	SET_BOOL(client_cert_ok);
	SET_BOOL(authentication_success);
	SET_BOOL(quick_session_tickets);
	SET_BOOL(fragment);
	SET_BOOL(length_flag);
	SET_BOOL(allow_session_resumption);
	SET_BOOL(session_not_resumed);

	SET_INT(mtu);
	SET_INT(tls_msg_len);
	SET_INT(peap_flag);

	//talloc_set_destructor(state, _tls_session_free);
#undef SET_BOOL
#undef SET_INT
	return 1;
}
