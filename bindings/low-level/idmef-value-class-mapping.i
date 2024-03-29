
/*****
*
* Copyright (C) 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv@gmail.com>
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

/* Auto-generated by the GenerateIDMEFValueClassSwigMapping package */



%{

void *swig_idmef_value_get_descriptor(idmef_value_t *value)
{
        unsigned int i = 0;
        idmef_class_id_t wanted_class = idmef_value_get_class(value);
	const struct {
	        idmef_class_id_t classid;
	        const char *classname;
	} tbl[] = {
                { IDMEF_CLASS_ID_ADDITIONAL_DATA, "idmef_additional_data_t *" },
                { IDMEF_CLASS_ID_CLASSIFICATION, "idmef_classification_t *" },
                { IDMEF_CLASS_ID_USER_ID, "idmef_user_id_t *" },
                { IDMEF_CLASS_ID_USER, "idmef_user_t *" },
                { IDMEF_CLASS_ID_ADDRESS, "idmef_address_t *" },
                { IDMEF_CLASS_ID_PROCESS, "idmef_process_t *" },
                { IDMEF_CLASS_ID_WEB_SERVICE, "idmef_web_service_t *" },
                { IDMEF_CLASS_ID_SNMP_SERVICE, "idmef_snmp_service_t *" },
                { IDMEF_CLASS_ID_SERVICE, "idmef_service_t *" },
                { IDMEF_CLASS_ID_NODE, "idmef_node_t *" },
                { IDMEF_CLASS_ID_SOURCE, "idmef_source_t *" },
                { IDMEF_CLASS_ID_FILE_ACCESS, "idmef_file_access_t *" },
                { IDMEF_CLASS_ID_INODE, "idmef_inode_t *" },
                { IDMEF_CLASS_ID_FILE, "idmef_file_t *" },
                { IDMEF_CLASS_ID_LINKAGE, "idmef_linkage_t *" },
                { IDMEF_CLASS_ID_TARGET, "idmef_target_t *" },
                { IDMEF_CLASS_ID_ANALYZER, "idmef_analyzer_t *" },
                { IDMEF_CLASS_ID_ALERTIDENT, "idmef_alertident_t *" },
                { IDMEF_CLASS_ID_IMPACT, "idmef_impact_t *" },
                { IDMEF_CLASS_ID_ACTION, "idmef_action_t *" },
                { IDMEF_CLASS_ID_CONFIDENCE, "idmef_confidence_t *" },
                { IDMEF_CLASS_ID_ASSESSMENT, "idmef_assessment_t *" },
                { IDMEF_CLASS_ID_TOOL_ALERT, "idmef_tool_alert_t *" },
                { IDMEF_CLASS_ID_CORRELATION_ALERT, "idmef_correlation_alert_t *" },
                { IDMEF_CLASS_ID_OVERFLOW_ALERT, "idmef_overflow_alert_t *" },
                { IDMEF_CLASS_ID_ALERT, "idmef_alert_t *" },
                { IDMEF_CLASS_ID_HEARTBEAT, "idmef_heartbeat_t *" },
                { IDMEF_CLASS_ID_MESSAGE, "idmef_message_t *" },
                { IDMEF_CLASS_ID_REFERENCE, "idmef_reference_t *" },
                { IDMEF_CLASS_ID_CHECKSUM, "idmef_checksum_t *" },
                { 0, NULL }
        };

        for ( i = 0; tbl[i].classname != NULL; i++ ) {
                if ( tbl[i].classid == wanted_class )
		        return SWIG_TypeQuery(tbl[i].classname);
        }

        return NULL;
}

%}
