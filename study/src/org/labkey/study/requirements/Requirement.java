/*
 * Copyright (c) 2007-2008 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.labkey.study.requirements;

import org.labkey.api.data.Container;
import org.labkey.api.security.User;
import org.labkey.study.model.SampleRequestActor;

/**
 * User: brittp
 * Date: Jun 4, 2007
 * Time: 2:31:52 PM
 */
public interface Requirement<R extends Requirement>
{
    String getOwnerEntityId();

    void setOwnerEntityId(String entityId);

    Container getContainer();

    Object getActorPrimaryKey();

    boolean isComplete();

    R update(User user);

    R createMutable();

    boolean isEqual(R requirement);

    void delete();

    R persist(User user, String ownerEntityId);
}
