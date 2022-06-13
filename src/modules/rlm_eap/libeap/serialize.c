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

#define SET_BOOL(n, t) do {\
	MEM(val = json_object_new_boolean((t->n)));\
	json_object_object_add(obj, #n, val);\
} while(0)

#define SET_INT(n, t) do {\
	MEM(val = json_object_new_int64((t->n)));\
	json_object_object_add(obj, #n, val);\
} while(0)

#define GET_INT(f, t) do {\
	uint64_t num;\
	if (!json_object_object_get_ex(obj, #f, &val)) {\
		RERROR("Cannot find " #f " for info");\
		return 0;\
	}\
	num = json_object_get_int64(val);\
	t->f = num;\
	RDEBUG("Setting " #f "with %ld ", num);\
} while(0)

#define GET_BOOL(f, t) do {\
	if (!json_object_object_get_ex(obj, #f, &val)) {\
		RERROR("Cannot find " #f);\
		return 0;\
	}\
	\
	t->f = json_object_get_boolean(val);\
} while(0)


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

static int serialize_tls_info(json_object *parent, const char* name, tls_info_t *info)
{

	json_object *val, *obj;

	MEM(obj = json_object_new_object());
	json_object_object_add(parent, name, obj);

	SET_INT(origin, info);
	SET_INT(content_type, info);
	SET_INT(handshake_type, info);
	SET_INT(alert_level, info);
	SET_INT(alert_description, info);
	SET_INT(record_len, info);
	SET_BOOL(initialized, info);
	MEM(val = json_object_new_string(info->info_description));
	json_object_object_add(obj, "info_description", val);

	return 0;
}

static int deserialize_tls_info(REQUEST* request, json_object *parent, const char* name, tls_info_t *info)
{
	json_object *val, *obj = NULL;

	if (!json_object_object_get_ex(parent, name, &obj)) {
			return 1;
	}

	GET_INT(origin, info);
	GET_INT(content_type, info);
	GET_INT(handshake_type, info);
	GET_INT(alert_level, info);
	GET_INT(alert_description, info);
	GET_INT(record_len, info);
	GET_BOOL(initialized, info);

	return 0;
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

static int deserialize_record_t(json_object *obj, const char* name, record_t * record)
{
	json_object *val;
	const char *data;
	size_t len;

	if (!json_object_object_get_ex(obj, name, &val)) {
	empty:
		record->used = 0;
		return 1;
	}

	data = json_object_get_string(val);
	if (!data) goto empty;

	len = json_object_get_string_len(val);
	if (!len) goto empty;

	fr_hex2bin(record->data, MAX_RECORD_SIZE, data, len);
	return 1;
}

static int serialize_bio(json_object *obj, const char* name, BIO *bio)
{
	json_object *val;
	char *data;
	BUF_MEM *mem;

	if (bio == NULL) {
		return 0;
	}

	BIO_get_mem_ptr(bio, &mem);
	if (mem->length == 0) {
		return 0;
	}

	data = malloc(mem->length * 2);
	fr_bin2hex(data, (uint8_t *) mem->data, mem->length);
	MEM(val = json_object_new_string_len(data, mem->length * 2));
	json_object_object_add(obj, name, val);
	free(data);
	return 0;
}

int serialize_tls_session(UNUSED REQUEST *request, UNUSED void *instance, UNUSED REQUEST *fake, json_object *obj, tls_session_t *ssn)
{
	VALUE_PAIR *vp;
	json_object *val;
	unsigned char *ptr = NULL;
	size_t len, blob_len;

	if (ssn->ssl) {

		if (ssn->ssl_session ) {
			vp = fr_pair_afrom_num(fake->reply, PW_EAP_SERIALIZED_TLS_TIME, 0);
			if (!vp) return 0;

			vp->vp_integer64 = SSL_SESSION_get_time(ssn->ssl_session);
			fr_pair_add(&fake->reply->vps, vp);

			vp = fr_pair_afrom_num(fake->reply, PW_EAP_SERIALIZED_TLS_SESSION, 0);
			if (!vp) return 0;
			len = i2d_SSL_SESSION(ssn->ssl_session, NULL);
			if (len >= 1) {

				/* Do not convert to TALLOC - Thread safety */
				/* alloc and convert to ASN.1 */
				ptr = malloc(len);
				if (!ptr) {
					RDEBUG("(TLS) Session serialisation failed, couldn't allocate buffer (%ld bytes)", len);
					return 0;
				}

				blob_len = i2d_SSL_SESSION(ssn->ssl_session, &ptr);
				if (len != blob_len) {
					if (request) RWDEBUG("(TLS) Session serialisation failed");
					return 0;
				}

				fr_pair_value_memcpy(vp, ptr, len);
				fr_pair_add(&fake->reply->vps, vp);
				free(ptr);
			}
		}
	}

	serialize_bio(obj, "into_ssl", ssn->into_ssl);
	serialize_bio(obj, "from_ssl", ssn->from_ssl);
	serialize_tls_info(obj, "info", &ssn->info);
	serialize_record_t(obj, "clean_in", &ssn->clean_in);
	serialize_record_t(obj, "clean_out", &ssn->clean_out);
	serialize_record_t(obj, "dirty_in", &ssn->dirty_in);
	serialize_record_t(obj, "dirty_out", &ssn->dirty_out);
	SET_BOOL(invalid_hb_used, ssn);
	SET_BOOL(connected, ssn);
	SET_BOOL(is_init_finished, ssn);
	SET_BOOL(client_cert_ok, ssn);
	SET_BOOL(authentication_success, ssn);
	SET_BOOL(quick_session_tickets, ssn);
	SET_BOOL(fragment, ssn);
	SET_BOOL(length_flag, ssn);
	SET_BOOL(allow_session_resumption, ssn);
	SET_BOOL(session_not_resumed, ssn);

	SET_INT(mtu, ssn);
	SET_INT(tls_msg_len, ssn);
	SET_INT(peap_flag, ssn);
	return 1;
}

static int deserialize_bio(UNUSED REQUEST *request, json_object *obj, const char *name, BIO *bio)
{
	json_object *val;
	BUF_MEM *mem;
	size_t len;
	const char *data;

	if (!bio) return 1;

	if (!json_object_object_get_ex(obj, name, &val)) {
			return 1;
	}

	data = json_object_get_string(val);
	if (!data) return 1;

	len = json_object_get_string_len(val);
	if (!len) return 1;

	mem = BUF_MEM_new();
	BUF_MEM_grow(mem, len/2);
	fr_hex2bin((uint8_t *) mem->data, mem->length, data, len);
	BIO_set_mem_buf(bio, mem, BIO_CLOSE);
	return 1;
}

int deserialize_tls_session(REQUEST *request, UNUSED void *instance, UNUSED REQUEST *fake, json_object *obj, tls_session_t *ssn)
{
	json_object *val;

	deserialize_tls_info(request, obj, "info", &ssn->info);
	deserialize_bio(request, obj, "into_ssl", ssn->into_ssl);
	deserialize_bio(request, obj, "from_ssl", ssn->from_ssl);
	deserialize_record_t(obj, "clean_in", &ssn->clean_in);
	deserialize_record_t(obj, "clean_out", &ssn->clean_out);
	deserialize_record_t(obj, "dirty_in", &ssn->dirty_in);
	deserialize_record_t(obj, "dirty_out", &ssn->dirty_out);
	GET_BOOL(invalid_hb_used, ssn);
	GET_BOOL(connected, ssn);
	GET_BOOL(is_init_finished, ssn);
	GET_BOOL(client_cert_ok, ssn);
	GET_BOOL(authentication_success, ssn);
	GET_BOOL(quick_session_tickets, ssn);
	GET_BOOL(fragment, ssn);
	GET_BOOL(length_flag, ssn);
	GET_BOOL(allow_session_resumption, ssn);
	GET_BOOL(session_not_resumed, ssn);

	GET_INT(mtu, ssn);
	GET_INT(tls_msg_len, ssn);
	GET_INT(peap_flag, ssn);

	return 1;
}
