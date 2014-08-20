/*
 * Copyright (c) 2014 LabKey Corporation
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
package org.labkey.api.data;

import org.jetbrains.annotations.Nullable;

/**
* User: adam
* Date: 1/17/14
* Time: 3:20 PM
*/
public enum PHI
{
    NotPHI(0),
    Limited(1),
    PHI(2),
    Restricted(3);

    public static PHI fromString(@Nullable String value)
    {
        for (PHI phi : values())
            if (phi.name().equals(value))
                return phi;

        return null;
    }

    private final int rank;
    private PHI(int rank) {
        this.rank = rank;
    }
    public int getRank() {
        return rank;
    }
    public boolean isLevelAllowed(PHI level) { return this.rank <= level.getRank(); }
}
