/*****
*
* Copyright (C) 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Nicolas Delon 
*
* This file is part of the Requiem library.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by 
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#define inline 

%{
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#include "requiem.h"
#include "requiem-log.h"
#include "requiem-msg.h"
#include "requiem-option.h"
#include "requiem-option-wide.h"
#include "idmef.h"
#include "idmef-message-write.h"
#include "idmef-message-print.h"
#include "idmef-additional-data.h"
#include "idmef-tree-wrap.h"
#include "requiem-inttypes.h"
%}


%constant int IDMEF_LIST_APPEND = IDMEF_LIST_APPEND;
%constant int IDMEF_LIST_PREPEND = IDMEF_LIST_PREPEND;


typedef char int8_t;
typedef unsigned char uint8_t;

typedef short int16_t;
typedef unsigned short uint16_t;

typedef int int32_t;
typedef unsigned int uint32_t;

typedef long long int64_t;
typedef unsigned long long uint64_t;

%ignore requiem_error_t;
typedef signed int requiem_error_t;

typedef enum { 
	REQUIEM_BOOL_TRUE = TRUE, 
	REQUIEM_BOOL_FALSE = FALSE 
} requiem_bool_t;

%typemap(in, numinputs=0) (uint64_t *source_id, uint32_t *request_id, void **value) (uint64_t tmp_source_id, uint32_t tmp_request_id, void *tmp_value) {
	tmp_source_id = 0;
	tmp_request_id = 0;
	$1 = &tmp_source_id;
	$2 = &tmp_request_id;
	$3 = &tmp_value;
};



%include idmef-value-class-mapping.i


#ifdef SWIGPYTHON
%include librequiem-python.i
#endif /* ! SWIGPYTHON */


#ifdef SWIGPERL
%include perl/librequiem_perl.i
#endif /* ! SWIGPERL */

/*
 * Double pointer typemap
 */
%apply SWIGTYPE **OUTPARAM {
	requiem_client_t **,
	requiem_client_profile_t **, 
	requiem_msgbuf_t **,
	requiem_msg_t **,
	requiem_connection_t **,
	idmef_path_t **,
	idmef_value_t **,
	idmef_criteria_t **,
	idmef_time_t **,
        idmef_data_t **
};


%apply SWIGTYPE **OUTPARAM {
	idmef_additional_data_t **,
	idmef_reference_t **,
	idmef_classification_t **,
	idmef_user_id_t **,
	idmef_user_t **,
	idmef_address_t **,
	idmef_process_t **,
	idmef_web_service_t **,
	idmef_snmp_service_t **,
	idmef_service_t **,
	idmef_node_t **,
	idmef_source_t **,
	idmef_file_access_t **,
	idmef_inode_t **,
	idmef_linkage_t **,
	idmef_checksum_t **,
	idmef_file_t **,
	idmef_target_t **,
	idmef_analyzer_t **,
	idmef_alertident_t **,
	idmef_impact_t **,
	idmef_action_t **,
	idmef_confidence_t **,
	idmef_assessment_t **,
	idmef_tool_alert_t **,
	idmef_correlation_alert_t **,
	idmef_overflow_alert_t **,
	idmef_alert_t **,
	idmef_heartbeat_t **,
	idmef_message_t **
};

/*
 * Check for nil input
 */
%apply SWIGTYPE *INPARAM {
	idmef_additional_data_t *,
	idmef_reference_t *,
	idmef_classification_t *,
	idmef_user_id_t *,
	idmef_user_t *,
	idmef_address_t *,
	idmef_process_t *,
	idmef_web_service_t *,
	idmef_snmp_service_t *,
	idmef_service_t *,
	idmef_node_t *,
	idmef_source_t *,
	idmef_file_access_t *,
	idmef_inode_t *,
	idmef_linkage_t *,
	idmef_checksum_t *,
	idmef_file_t *,
	idmef_target_t *,
	idmef_analyzer_t *,
	idmef_alertident_t **,
	idmef_impact_t *,
	idmef_action_t *,
	idmef_confidence_t *,
	idmef_assessment_t *,
	idmef_tool_alert_t *,
	idmef_correlation_alert_t *,
	idmef_overflow_alert_t *,
	idmef_alert_t *,
	idmef_heartbeat_t *,
	idmef_message_t *,
	requiem_client_t *,
	requiem_client_profile_t *, 
	requiem_msgbuf_t *,
	requiem_msg_t *,
	requiem_connection_t *,
	idmef_path_t *,
	idmef_value_t *,
	idmef_criteria_t *,
	idmef_time_t *,
        idmef_data_t *
};

/* the following typemaps are used to allow NULL pointers to be passed
 * to _get_next_* functions
 */
%apply SWIGTYPE *LISTEDPARAM {
        idmef_reference_t *reference_cur,
        idmef_user_id_t *user_id_cur,
        requiem_string_t *requiem_string_cur,
        idmef_address_t *address_cur,
        idmef_file_access_t *file_access_cur,
        idmef_linkage_t *linkage_cur,
        idmef_checksum_t *checksum_cur,
        idmef_file_t *file_cur,
        idmef_action_t *action_cur,
        idmef_alertident_t *alertident_cur,
        idmef_analyzer_t *analyzer_cur,
        idmef_source_t *source_cur,
        idmef_target_t *target_cur,
        idmef_additional_data_t *additional_data_cur
};

/* For functions returning pointer to integer, return the integer
 * or the NULL equivalent directly
 */
%apply INTPOINTER * {
        int8_t *,
        int16_t *,
        int32_t *
};

%apply UINTPOINTER * {
        uint8_t *,
        uint16_t *,
        uint32_t *
};

%apply INT64POINTER * {
        int64_t *
};

%apply UINT64POINTER * {
        uint64_t *
};



%ignore idmef_path_new_v;
%ignore requiem_string_vprintf;
%ignore _requiem_log_v;
%ignore requiem_error_verbose_make_v;


%include "requiem.h"
%include "requiem-client.h"
%include "requiem-client-profile.h"
%include "idmef-tree-wrap.h"
%include "idmef-value.h"
%include "idmef-path.h"
%include "idmef-time.h"
%include "idmef-data.h"
%include "idmef-criteria.h"
%include "idmef-message-read.h"
%include "idmef-message-write.h"
%include "idmef-additional-data.h"
%include "idmef-value-type.h"
%include "idmef-class.h"
%include "requiem-connection.h"
%include "requiem-connection-pool.h"
%include "requiem-option.h"
%include "requiem-option-wide.h"
%include "requiem-msg.h"
%include "requiem-message-id.h"
%include "requiem-log.h"
%include "requiem-msgbuf.h"
%include "requiem-timer.h"
%include "requiem-error.h"

typedef signed int requiem_error_t;
