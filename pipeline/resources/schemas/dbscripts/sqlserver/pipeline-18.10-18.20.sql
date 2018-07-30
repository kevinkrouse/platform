/*
 * Copyright (c) 2017 LabKey Corporation
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

/* pipeline-18.10-18.11.sql */

CREATE TABLE pipeline.TriggeredFiles
(
  RowId INT IDENTITY(1,1) NOT NULL,
  Container ENTITYID NOT NULL,
  TriggerId INT NOT NULL,
  FilePath NVARCHAR(1000) NOT NULL,
  LastRun DATETIME,

  CONSTRAINT PK_TriggeredFiles PRIMARY KEY (RowId),
  CONSTRAINT FK_TriggeredFiles_TriggerId FOREIGN KEY (TriggerId) REFERENCES pipeline.TriggerConfigurations(RowId),
  CONSTRAINT FK_TriggeredFiles_Container FOREIGN KEY (Container) REFERENCES core.Containers (ENTITYID),
  CONSTRAINT UQ_TriggeredFiles_Container_TriggerId_FilePath UNIQUE (Container, TriggerId, FilePath)
);