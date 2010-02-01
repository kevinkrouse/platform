/*
 * Copyright (c) 2010 LabKey Corporation
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

CREATE SCHEMA filecontent;

CREATE TABLE filecontent.FileRoots (
   RowId SERIAL,
   Container ENTITYID NOT NULL,
   Path VARCHAR(255),
   Type VARCHAR(50),
   Properties TEXT,

   Enabled BOOLEAN NOT NULL DEFAULT TRUE,
   UseDefault BOOLEAN NOT NULL DEFAULT FALSE,

   CONSTRAINT PK_FileRoots PRIMARY KEY (RowId)
);

INSERT INTO filecontent.FileRoots (Container, Path, Type)
  SELECT core.Containers.EntityId as Container, prop.Properties.Value as Path, '@files'
  FROM prop.Properties INNER JOIN
    prop.PropertySets ON prop.Properties.Set = prop.PropertySets.Set INNER JOIN
    core.Containers ON prop.PropertySets.ObjectId = core.Containers.EntityId
  WHERE (prop.PropertySets.Category = 'staticFile' AND prop.Properties.Name = 'root');

DELETE FROM prop.Properties
  WHERE prop.Properties.Set IN
    (SELECT Set FROM prop.PropertySets WHERE prop.PropertySets.Category = 'staticFile');

DELETE FROM prop.PropertySets WHERE prop.PropertySets.Category = 'staticFile';
