/*
 * Copyright (c) 2008 LabKey Corporation
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

/* mothership-8.30-8.31.sql */

-- Migrate from using just the SVN revision to tracking the revision and URL.

-- Make sure that we're a real FK to container
DELETE FROM mothership.softwarerelease WHERE Container NOT IN (SELECT EntityId FROM core.containers)
GO

ALTER TABLE mothership.softwarerelease ADD CONSTRAINT FK_SoftwareRelease_Container
    FOREIGN KEY (Container) REFERENCES core.containers(EntityId)
GO

-- Handle null revisions, which happens when building from a source distribution instead of SVN
ALTER TABLE mothership.SoftwareRelease ALTER COLUMN SVNRevision INT NULL
GO

-- Make sure that we have a release entry for every report we've gotten
INSERT INTO mothership.SoftwareRelease (Container, SVNRevision, Description)
    SELECT DISTINCT si.Container, ss.SVNRevision, CASE WHEN ss.SVNRevision IS NULL THEN 'NotSvn' ELSE CAST(ss.SVNRevision AS NVARCHAR(50)) END
        FROM mothership.ServerSession ss, mothership.ServerInstallation si
        WHERE si.ServerInstallationId = ss.ServerInstallationId AND SVNRevision NOT IN
            (SELECT SVNRevision FROM mothership.SoftwareRelease sr WHERE sr.Container = si.Container)
GO

DELETE FROM mothership.SoftwareRelease WHERE SVNRevision IS NULL
GO

INSERT INTO mothership.SoftwareRelease (Container, SVNRevision, Description)
    SELECT TOP 1 Container, NULL as Revision, 'NotSVN' as Description FROM mothership.ServerSession
GO

-- Change the PK
ALTER TABLE mothership.ServerSession ADD SoftwareReleaseId INT
GO
ALTER TABLE mothership.SoftwareRelease DROP CONSTRAINT pk_softwarerelease
GO
ALTER TABLE mothership.SoftwareRelease DROP COLUMN ReleaseId
GO
ALTER TABLE mothership.SoftwareRelease ADD SoftwareReleaseId INT IDENTITY
GO
ALTER TABLE mothership.SoftwareRelease ADD CONSTRAINT pk_softwarerelease PRIMARY KEY (SoftwareReleaseId)
GO

-- Point to the row in the release table
UPDATE mothership.ServerSession SET SoftwareReleaseId =
    (SELECT sr.SoftwareReleaseId FROM mothership.SoftwareRelease sr
        WHERE (sr.SVNRevision = mothership.ServerSession.SVNRevision OR (sr.SVNRevision IS NULL AND mothership.ServerSession.SVNRevision IS NULL)) AND
            mothership.ServerSession.Container = sr.Container)
GO

ALTER TABLE mothership.ServerSession ALTER COLUMN SoftwareReleaseId INT NOT NULL
GO

ALTER TABLE mothership.SoftwareRelease ADD SVNURL NVARCHAR(200)
GO

ALTER TABLE mothership.SoftwareRelease DROP CONSTRAINT uq_softwarerelease
GO
ALTER TABLE mothership.SoftwareRelease ADD CONSTRAINT uq_softwarerelease UNIQUE (container, svnrevision, svnurl)
GO

ALTER TABLE mothership.ServerSession DROP COLUMN SVNRevision
GO

ALTER TABLE mothership.serversession ADD CONSTRAINT FK_ServerSession_SoftwareRelease FOREIGN KEY (SoftwareReleaseId)
    REFERENCES mothership.SoftwareRelease(SoftwareReleaseId)
GO