CREATE VIEW comm.Threads AS
    SELECT y.RowId, y.EntityId, y.Container, y.Body, y.RendererType, PropsId AS LatestId, props.Title, props.AssignedTo,
        props.Status, props.Expires, props.CreatedBy AS ResponseCreatedBy, props.Created AS ResponseCreated,
        y.DiscussionSrcIdentifier, y.DiscussionSrcURL, y.CreatedBy, y.Created,
        (SELECT COUNT(*) FROM comm.Announcements WHERE Parent = y.EntityId) AS ResponseCount FROM
    (
        SELECT *, CASE WHEN LastResponseId IS NULL THEN x.RowId ELSE LastResponseId END AS PropsId FROM
        (
            SELECT *, (SELECT MAX(RowId) FROM comm.Announcements response WHERE response.Parent = message.EntityId) AS LastResponseId
            FROM comm.Announcements message
            WHERE Parent IS NULL
        ) x
    ) y LEFT OUTER JOIN comm.Announcements props ON props.RowId = PropsId
GO
