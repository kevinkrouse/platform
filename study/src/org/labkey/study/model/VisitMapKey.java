/*
 * Copyright (c) 2006-2007 LabKey Corporation
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

package org.labkey.study.model;

/**
 * Created by IntelliJ IDEA.
 * User: Matthew
 * Date: Feb 1, 2006
 * Time: 10:12:34 AM
 */
public class VisitMapKey implements Comparable
{
    public VisitMapKey(Integer datasetId, Integer visitRowId)
    {
        this.datasetId = datasetId == null ? 0 : datasetId;
        this.visitRowId = visitRowId == null ? 0 : visitRowId;
    }

    public VisitMapKey(int datasetId, int visitRowId)
    {
        this.datasetId = datasetId;
        this.visitRowId = visitRowId;
    }

    public boolean equals(Object obj)
    {
        VisitMapKey b = (VisitMapKey)obj;
        return this.datasetId == b.datasetId && this.visitRowId == b.visitRowId;
    }

    public int hashCode()
    {
        return datasetId * 4093 + visitRowId;
    }

    public int compareTo(Object o)
    {
        VisitMapKey k = (VisitMapKey) o;
        return this.visitRowId != k.visitRowId ? this.visitRowId - k.visitRowId :
                this.datasetId - k.datasetId;
    }

    public int datasetId;
    public int visitRowId;
}
