// GraphSentry schema and core graph queries. The app runs parameterized versions of these.

// 1. Seed/model examples (synthetic values only)
MERGE (a:Alert {id: 'AL-104'}) SET a.title = 'Suspicious privileged login';
MERGE (ip:IP {address: '203.0.113.77'}) SET ip.reputation = 'known-bad';
MERGE (u:Account {username: 'maya.admin'}) SET u.privilege = 'admin';
MERGE (d:Device {device_id: 'LAPTOP-UNKNOWN-09'}) SET d.trust = 'untrusted';
MERGE (r:Role {name: 'Platform Admin'});
MERGE (p:Project {name: 'payments-prod'}) SET p.environment = 'production';
MERGE (s:Service {name: 'Payments API'}) SET s.criticality = 'critical';
MERGE (db:Service {name: 'Customer DB'}) SET db.criticality = 'critical';
MERGE (a)-[:ORIGINATED_FROM]->(ip);
MERGE (a)-[:TARGETS]->(u);
MERGE (u)-[:USED_DEVICE]->(d);
MERGE (u)-[:HAS_ROLE]->(r);
MERGE (u)-[:CAN_ACCESS]->(p);
MERGE (p)-[:HOSTS]->(s);
MERGE (s)-[:DEPENDS_ON]->(db);

// 2. Multi-hop context: the target account's role, device, and source IP.
MATCH (a:Alert {id: $alert_id})-[:ORIGINATED_FROM]->(ip:IP)
MATCH (a)-[:TARGETS]->(u:Account)
OPTIONAL MATCH (u)-[:USED_DEVICE]->(d:Device)
OPTIONAL MATCH (u)-[:HAS_ROLE]->(r:Role)
RETURN a.id, ip.address, ip.reputation, u.username, u.privilege,
       d.device_id, d.trust, collect(DISTINCT r.name) AS roles;

// 3. Find accounts connected to the same source IP.
MATCH (a:Alert {id: $alert_id})-[:ORIGINATED_FROM]->(ip:IP)-[:SEEN_WITH]->(other:Account)
RETURN ip.address, collect(DISTINCT other.username) AS accounts,
       count(DISTINCT other.username) AS account_count;

// 4. Trace accessible projects to hosted services and downstream dependencies.
MATCH (a:Alert {id: $alert_id})-[:TARGETS]->(u:Account)-[:CAN_ACCESS]->(p:Project)-[:HOSTS]->(s:Service)
OPTIONAL MATCH (s)-[:DEPENDS_ON*1..3]->(d:Service)
RETURN DISTINCT u.username, p.name, s.name, d.name, d.criticality;

// 5. Action logging: an action node linked to both the alert and affected account.
MATCH (a:Alert {id: $alert_id}), (u:Account {username: $username})
CREATE (ra:ResponseAction {id: $action_id, kind: 'SIMULATED_CONTAINMENT',
       status: 'SIMULATED_APPROVED', target: $username, rationale: $rationale,
       created_at: $created_at})
CREATE (a)-[:HAS_RESPONSE_ACTION]->(ra)
CREATE (ra)-[:TARGETS_ACCOUNT]->(u)
RETURN ra.id, ra.status, ra.target;

// 6. Matched indicators: retrieve threat indicators connected to the alert.
MATCH (a:Alert {id: $alert_id})-[r:MATCHES_INDICATOR|OBSERVED_ON]->(i:Indicator)
RETURN DISTINCT i.value AS value, i.indicator_type AS indicator_type,
       type(r) AS relationship, i.confidence AS confidence,
       i.severity AS severity, i.description AS description
ORDER BY value;

