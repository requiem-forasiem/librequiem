/*****
*
* Copyright (C) 2008 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_IDMEF_PATH_HXX
#define _LIBREQUIEM_IDMEF_PATH_HXX

#include "requiem.h"
#include "idmef-path.h"

#include "idmef.hxx"
#include "requiem-error.hxx"
#include "idmef-value.hxx"


namespace Requiem {
        class IDMEFPath {
            private:
                idmef_path_t *_path;

            public:
                IDMEFPath(const char *buffer);
                IDMEFPath(idmef_path_t *path);
                IDMEFPath(const IDMEFPath &path);
                ~IDMEFPath();

                Requiem::IDMEFValue Get(Requiem::IDMEF &message);
                void Set(Requiem::IDMEF &message, std::vector<Requiem::IDMEFValue> value);
                void Set(Requiem::IDMEF &message, Requiem::IDMEFValue *value);
                void Set(Requiem::IDMEF &message, Requiem::IDMEFValue &value);
                void Set(Requiem::IDMEF &message, Requiem::IDMEFTime &time);
                void Set(Requiem::IDMEF &message, std::string value);
                void Set(Requiem::IDMEF &message, const char *value);
                void Set(Requiem::IDMEF &message, int8_t value);
                void Set(Requiem::IDMEF &message, uint8_t value);
                void Set(Requiem::IDMEF &message, int16_t value);
                void Set(Requiem::IDMEF &message, uint16_t value);
                void Set(Requiem::IDMEF &message, int32_t value);
                void Set(Requiem::IDMEF &message, uint32_t value);
                void Set(Requiem::IDMEF &message, int64_t value);
                void Set(Requiem::IDMEF &message, uint64_t value);
                void Set(Requiem::IDMEF &message, float value);
                void Set(Requiem::IDMEF &message, double value);

                idmef_class_id_t GetClass(int depth=-1);
                idmef_value_type_id_t GetValueType(int depth=-1);
                int SetIndex(unsigned int index, int depth=-1);
                int UndefineIndex(int depth=-1);
                int GetIndex(int depth=-1);
                int MakeChild(const char *child_name, unsigned int index);
                int MakeParent();
                int Compare(IDMEFPath *path, int depth=-1);
                IDMEFPath Clone();

                int CheckOperator(idmef_criterion_operator_t op);
                idmef_criterion_operator_t GetApplicableOperators();

                //ref ?
                const char *GetName(int depth=-1);
                bool IsAmbiguous();
                int HasLists();
                bool IsList(int depth=-1);
                unsigned int GetDepth();

                IDMEFPath &operator = (const IDMEFPath &path);
        };
};

#endif
