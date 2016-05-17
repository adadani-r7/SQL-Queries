with severity AS (
 SELECT vulnerability_id, riskscore,
 CASE WHEN riskscore >= 900 THEN 'Critical'
 WHEN riskscore >= 600 AND riskscore < 900 THEN 'High'
 WHEN riskscore >= 400 AND riskscore < 600 THEN 'Medium'
 WHEN riskscore >= 1 AND riskscore < 400 THEN 'Low'
 ELSE 'Informational'
 END AS severity
 FROM dim_vulnerability
)
SELECT COUNT(DISTINCT(da.ip_address)), se.severity
FROM fact_asset_vulnerability_finding AS favf
JOIN severity AS se USING (vulnerability_id)
JOIN dim_asset AS da USING (asset_id)
GROUP BY severity