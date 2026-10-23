"""
Offline client that serves CA Insight data from a roadrecon database.

RoadreconClient has the same public methods as GraphAPIClient, but reads from the
SQLite database written by `roadrecon gather` instead of calling MS Graph. No
access token is needed and no network calls are made.

Data that roadrecon does not collect (authentication contexts, agent identities,
agent blueprints, PIM for Groups eligibility) is returned as an empty list, with a
one-line warning.
"""

# Standard library imports
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set, Callable

# Local imports
from .api_client import GraphAPIClient, SPECIAL_CA_VALUES
from .roadrecon_translator import (
    PolicyTranslator,
    POLICY_TYPE_AUTH_STRENGTH,
    POLICY_TYPE_CONDITIONAL_ACCESS,
    POLICY_TYPE_NAMED_LOCATION,
)


class _NoNetworkSession:
    """Stand-in for requests.Session that refuses all requests.

    Inherited GraphAPIClient code paths that are not overridden would fail here
    instead of silently calling MS Graph.
    """

    def __getattr__(self, name):
        def _refuse(*args, **kwargs):
            raise RuntimeError(f"Network call attempted in roadrecon mode (session.{name})")
        return _refuse


class RoadreconClient(GraphAPIClient):
    """Client that reads Conditional Access data from a roadrecon database"""

    # Link tables that hold group and role membership, with the member object type
    GROUP_MEMBER_TABLES = {
        'lnk_group_member_user': ('User', '#microsoft.graph.user'),
        'lnk_group_member_group': ('childGroup', '#microsoft.graph.group'),
        'lnk_group_member_serviceprincipal': ('ServicePrincipal', '#microsoft.graph.servicePrincipal'),
        'lnk_group_member_device': ('Device', '#microsoft.graph.device'),
        'lnk_group_member_contact': ('Contact', '#microsoft.graph.orgContact'),
    }
    ROLE_MEMBER_TABLES = {
        'lnk_role_member_user': ('User', '#microsoft.graph.user'),
        'lnk_role_member_group': ('Group', '#microsoft.graph.group'),
        'lnk_role_member_serviceprincipal': ('ServicePrincipal', '#microsoft.graph.servicePrincipal'),
    }

    def __init__(self, db_path: str):
        """Open a roadrecon database read-only.

        Parameters:
            db_path (str): Path to the roadrecon.db file
        """
        path = Path(db_path).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"roadrecon database not found: {db_path}")

        self.db_path = path
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        # No token, no MS Graph domain, no HTTP session
        self.token = None
        self.msgraph_domain = None
        self.session = _NoNetworkSession()
        self.proxies = None
        self.verify_ssl = True

        self.cache_dir = Path("cache")
        self.cache_dir.mkdir(exist_ok=True)

        self._warned: Set[str] = set()
        self._group_members: Optional[Dict[str, List[Dict]]] = None
        self._role_members: Optional[Dict[str, List[Dict]]] = None

        tenant = self._query_one("SELECT objectId, verifiedDomains FROM TenantDetails")
        if tenant is None:
            raise ValueError("roadrecon database has no TenantDetails row. Was 'roadrecon gather' completed?")
        self.tenant_id = tenant['objectId']
        self._verified_domains = json.loads(tenant['verifiedDomains'] or '[]')

    # === Helpers ===

    def _warn_once(self, message: str):
        """Print a warning once per session."""
        if message not in self._warned:
            self._warned.add(message)
            print(f"Warning: {message}")

    def _query(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def _query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchone()

    def _cached(self, cache_file: Path, use_cache: bool, loader: Callable[[], List[Dict]]) -> List[Dict]:
        """Return cache_file contents if allowed, otherwise run loader and write the cache."""
        if use_cache and cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
        data = loader()
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2)
        return data

    @staticmethod
    def _json_list(value: Optional[str]) -> List:
        try:
            return json.loads(value) if value else []
        except json.JSONDecodeError:
            return []

    # === Graph-shaped object builders ===

    @staticmethod
    def _user(row: sqlite3.Row) -> Dict:
        return {
            '@odata.type': '#microsoft.graph.user',
            'id': row['objectId'],
            'displayName': row['displayName'],
            'userPrincipalName': row['userPrincipalName'],
            'userType': row['userType'],
            'accountEnabled': bool(row['accountEnabled']),
        }

    @classmethod
    def _group(cls, row: sqlite3.Row) -> Dict:
        return {
            '@odata.type': '#microsoft.graph.group',
            'id': row['objectId'],
            'displayName': row['displayName'],
            'securityEnabled': bool(row['securityEnabled']),
            'mailEnabled': bool(row['mailEnabled']),
            'groupTypes': cls._json_list(row['groupTypes']),
        }

    @classmethod
    def _service_principal(cls, row: sqlite3.Row) -> Dict:
        return {
            '@odata.type': '#microsoft.graph.servicePrincipal',
            'id': row['objectId'],
            'appId': row['appId'],
            'displayName': row['displayName'],
            'servicePrincipalType': row['servicePrincipalType'],
            'accountEnabled': bool(row['accountEnabled']),
            'appOwnerOrganizationId': row['appOwnerTenantId'],
            'tags': cls._json_list(row['tags']),
        }

    def _sp_rows(self, where: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self._query(
            "SELECT objectId, appId, displayName, servicePrincipalType, accountEnabled, "
            f"appOwnerTenantId, tags FROM ServicePrincipals WHERE {where}", params)

    def _user_rows(self, where: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self._query(
            "SELECT objectId, displayName, userPrincipalName, userType, accountEnabled "
            f"FROM Users WHERE {where}", params)

    def _group_rows(self, where: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self._query(
            "SELECT objectId, displayName, securityEnabled, mailEnabled, groupTypes "
            f"FROM Groups WHERE {where}", params)

    # === Token and tenant ===

    def validate_token(self) -> tuple[bool, str]:
        """No token in roadrecon mode; always valid."""
        return True, ""

    def _get_all_tenant_domains(self) -> set:
        """Get all verified domains from the TenantDetails table."""
        return {d.get('name') for d in self._verified_domains if d.get('name')}

    def get_primary_domain(self) -> Optional[str]:
        """Return the initial or default verified domain, matching ReportGenerator's MS Graph lookup."""
        for domain in self._verified_domains:
            if domain.get('initial') or domain.get('default'):
                return domain.get('name')
        return None

    # === Policies ===

    def _get_translator(self) -> PolicyTranslator:
        """Build a policy translator with the custom authentication strengths from the database."""
        auth_strengths = {}
        for row in self._query("SELECT objectId, displayName, policyIdentifier, policyDetail FROM Policys "
                               "WHERE policyType = ?", (POLICY_TYPE_AUTH_STRENGTH,)):
            strength = PolicyTranslator.translate_auth_strength(
                row['objectId'], row['displayName'], row['policyIdentifier'], row['policyDetail'])
            auth_strengths[strength['id']] = strength
        return PolicyTranslator(auth_strengths=auth_strengths, warn=self._warn_once)

    def get_all_policies(self, use_cache: bool = True) -> List[Dict]:
        """Load all CA policies (policyType 18) and translate them to the MS Graph format."""
        def load():
            translator = self._get_translator()
            policies = []
            for row in self._query("SELECT objectId, displayName, policyDetail FROM Policys "
                                   "WHERE policyType = ? ORDER BY displayName", (POLICY_TYPE_CONDITIONAL_ACCESS,)):
                policy = translator.translate_policy(row['objectId'], row['displayName'], row['policyDetail'])
                if policy:
                    policies.append(policy)
            return policies
        return self._cached(self.cache_dir / "policies" / "policies.json", use_cache, load)

    def get_named_locations(self, use_cache: bool = True) -> List[Dict]:
        """Load named locations (policyType 6) and translate them to the MS Graph format."""
        def load():
            translator = PolicyTranslator(warn=self._warn_once)
            locations = []
            for row in self._query("SELECT objectId, displayName, policyIdentifier, policyDetail FROM Policys "
                                   "WHERE policyType = ? ORDER BY displayName", (POLICY_TYPE_NAMED_LOCATION,)):
                locations.extend(translator.translate_named_locations(
                    row['objectId'], row['displayName'], row['policyIdentifier'], row['policyDetail']))
            return locations
        return self._cached(self.cache_dir / "tenant" / "named-locations.json", use_cache, load)

    def get_authentication_contexts(self, use_cache: bool = True) -> List[Dict]:
        """roadrecon does not collect authentication context class references."""
        self._warn_once("roadrecon does not collect authentication contexts, returning none")
        return self._cached(self.cache_dir / "policies" / "auth-contexts.json", use_cache, lambda: [])

    # === Tenant identities ===

    def get_all_active_members(self, use_cache: bool = True) -> List[Dict]:
        """Get all enabled users with userType Member."""
        return self._cached(
            self.cache_dir / "tenant" / "active-members.json", use_cache,
            lambda: [self._user(r) for r in self._user_rows("accountEnabled = 1 AND userType = 'Member'")])

    def get_all_active_guests(self, use_cache: bool = True) -> List[Dict]:
        """Get all enabled users with userType Guest."""
        return self._cached(
            self.cache_dir / "tenant" / "active-guests.json", use_cache,
            lambda: [self._user(r) for r in self._user_rows("accountEnabled = 1 AND userType = 'Guest'")])

    def get_b2b_collaboration_members(self, use_cache: bool = True) -> List[Dict]:
        """Get B2B collaboration members (userType Member from another tenant).

        roadrecon does not store the MS Graph 'identities' property, so external
        members are detected by the '#EXT#' marker in the userPrincipalName.
        """
        def load():
            members = self.get_all_active_members(use_cache=use_cache)
            return [m for m in members if '#EXT#' in (m.get('userPrincipalName') or '')]
        return self._cached(self.cache_dir / "tenant" / "b2b-collaboration-members.json", use_cache, load)

    def get_all_active_cloud_applications(self, use_cache: bool = True) -> List[Dict]:
        """Get all enabled service principals of type Application."""
        return self._cached(
            self.cache_dir / "tenant" / "active-cloud-apps.json", use_cache,
            lambda: [self._service_principal(r) for r in
                     self._sp_rows("accountEnabled = 1 AND servicePrincipalType = 'Application'")])

    def get_all_active_workload_identities(self, use_cache: bool = True) -> List[Dict]:
        """Get enabled single-tenant application service principals owned by this tenant."""
        return self._cached(
            self.cache_dir / "tenant" / "active-workload-identities.json", use_cache,
            lambda: [self._service_principal(r) for r in
                     self._sp_rows("accountEnabled = 1 AND servicePrincipalType = 'Application' "
                                   "AND appOwnerTenantId = ?", (self.tenant_id,))])

    def get_all_active_agent_identities(self, use_cache: bool = True) -> List[Dict]:
        """roadrecon does not collect agent identities."""
        self._warn_once("roadrecon does not collect agent identities, returning none")
        return self._cached(self.cache_dir / "tenant" / "active-agent-identities.json", use_cache, lambda: [])

    def get_all_active_agent_blueprints(self, use_cache: bool = True) -> List[Dict]:
        """roadrecon does not collect agent identity blueprints."""
        self._warn_once("roadrecon does not collect agent blueprints, returning none")
        return self._cached(self.cache_dir / "tenant" / "agent-blueprints.json", use_cache, lambda: [])

    # === Object resolution ===

    def resolve_object(self, object_id: str) -> Optional[Dict]:
        """Look up a directory object by ID in the users, groups, roles and service principal tables.

        Role IDs in CA policies are role template IDs, so those resolve to a
        directoryRoleTemplate object, as MS Graph /directoryObjects does.
        """
        if not object_id:
            return None
        rows = self._user_rows("objectId = ?", (object_id,))
        if rows:
            return self._user(rows[0])
        rows = self._group_rows("objectId = ?", (object_id,))
        if rows:
            return self._group(rows[0])
        row = self._query_one("SELECT templateId, displayName, description FROM RoleDefinitions "
                              "WHERE templateId = ? OR objectId = ?", (object_id, object_id))
        if row:
            return {
                '@odata.type': '#microsoft.graph.directoryRoleTemplate',
                'id': row['templateId'] or object_id,
                'displayName': row['displayName'],
                'description': row['description'],
            }
        row = self._query_one("SELECT objectId, displayName, description, roleTemplateId FROM DirectoryRoles "
                              "WHERE objectId = ? OR roleTemplateId = ?", (object_id, object_id))
        if row:
            return {
                '@odata.type': '#microsoft.graph.directoryRole',
                'id': row['objectId'],
                'displayName': row['displayName'],
                'description': row['description'],
                'roleTemplateId': row['roleTemplateId'],
            }
        rows = self._sp_rows("objectId = ?", (object_id,))
        if rows:
            return self._service_principal(rows[0])
        row = self._query_one("SELECT objectId, displayName FROM Devices WHERE objectId = ?", (object_id,))
        if row:
            return {'@odata.type': '#microsoft.graph.device', 'id': row['objectId'], 'displayName': row['displayName']}
        return None

    def resolve_objects(self, object_ids: List[str]) -> Tuple[List[Dict], Set[str]]:
        """Resolve several directory objects; unknown IDs are returned as deleted."""
        results = []
        deleted_ids = set()
        for oid in object_ids:
            obj = self.resolve_object(oid)
            if obj:
                results.append(obj)
            else:
                deleted_ids.add(oid)
        return results, deleted_ids

    def resolve_id(self, object_id: str, id_cache: Dict[str, str], location_map: Dict[str, str] = None) -> str:
        """Resolve a directory object ID to its display name."""
        if not object_id:
            return object_id
        if object_id in SPECIAL_CA_VALUES or (isinstance(object_id, str) and object_id.capitalize() in SPECIAL_CA_VALUES):
            return object_id
        if object_id in id_cache:
            return id_cache[object_id]
        if location_map and object_id in location_map:
            id_cache[object_id] = location_map[object_id]
            return location_map[object_id]
        obj = self.resolve_object(object_id) or {}
        name = obj.get('displayName') or obj.get('userPrincipalName') or obj.get('appId') or object_id
        id_cache[object_id] = name
        return name

    def resolve_service_principal(self, app_id: str) -> Optional[Dict]:
        """Find a service principal by appId."""
        rows = self._query("SELECT appId, displayName, objectId FROM ServicePrincipals WHERE appId = ?", (app_id,))
        if not rows:
            return None
        return {'appId': rows[0]['appId'], 'displayName': rows[0]['displayName'], 'id': rows[0]['objectId']}

    def resolve_service_principals_by_ids(self, sp_ids: List[str]) -> List[Dict]:
        """Find service principals by object ID; unknown IDs are skipped."""
        results = []
        for sp_id in sp_ids:
            if not sp_id:
                continue
            rows = self._sp_rows("objectId = ?", (sp_id,))
            if rows:
                results.append(self._service_principal(rows[0]))
        return results

    def resolve_agent_resources_by_ids(self, sp_ids: List[str]) -> List[Dict]:
        """roadrecon does not collect agent resources, so nothing resolves."""
        self._warn_once("roadrecon does not collect agent resources, returning none")
        return []

    # === Group and role membership ===

    def _load_membership(self, tables: Dict[str, Tuple[str, str]], parent_column: str) -> Dict[str, List[Dict]]:
        """Load link tables into a parent ID -> member list map (the tables have no index)."""
        members = defaultdict(list)
        existing = {r['name'] for r in self._query("SELECT name FROM sqlite_master WHERE type = 'table'")}
        for table, (column, odata_type) in tables.items():
            if table not in existing:
                continue
            for row in self._query(f'SELECT "{parent_column}" AS parent, "{column}" AS member FROM {table}'):
                if row['parent'] and row['member']:
                    members[row['parent']].append({'@odata.type': odata_type, 'id': row['member']})
        return members

    def get_group_members(self, group_id: str) -> List[Dict]:
        """Get the direct members of a group."""
        if self._group_members is None:
            self._group_members = self._load_membership(self.GROUP_MEMBER_TABLES, 'Group')
        return list(self._group_members.get(group_id, []))

    def get_directory_role_members(self, role_id: str) -> List[Dict]:
        """Get the members of an activated directory role by its object ID."""
        if self._role_members is None:
            self._role_members = self._load_membership(self.ROLE_MEMBER_TABLES, 'DirectoryRole')
        return list(self._role_members.get(role_id, []))

    def get_role_members(self, role_template_id: str) -> List[Dict]:
        """Get the members of an activated directory role by its role template ID."""
        row = self._query_one("SELECT objectId FROM DirectoryRoles WHERE roleTemplateId = ?", (role_template_id,))
        if not row:
            return []
        return self.get_directory_role_members(row['objectId'])

    def get_pim_eligible_role_members(self) -> Dict[str, Set[str]]:
        """Get PIM eligible role assignments as role template ID -> principal IDs."""
        eligible_map = defaultdict(set)
        rows = self._query(
            "SELECT e.principalId AS principal, COALESCE(r.templateId, e.roleDefinitionId) AS role "
            "FROM EligibleRoleAssignments e LEFT JOIN RoleDefinitions r ON r.objectId = e.roleDefinitionId")
        for row in rows:
            if row['role'] and row['principal']:
                eligible_map[row['role']].add(row['principal'])
        print(f"    ✓ Found {sum(len(v) for v in eligible_map.values())} PIM eligible role assignments")
        return dict(eligible_map)

    def get_pim_eligible_group_members(self) -> Dict[str, Set[str]]:
        """roadrecon does not collect PIM for Groups eligibility."""
        self._warn_once("roadrecon does not collect PIM for Groups eligibility, returning none")
        return {}

    # === Filter queries (used by filter files) ===

    @staticmethod
    def _parse_eq_filter(filter_query: str) -> Tuple[str, str]:
        """Parse a simple OData filter of the form "field eq 'value'"."""
        match = re.match(r"^\s*(\w+)\s+eq\s+'(.*)'\s*$", filter_query)
        if not match:
            raise ValueError(f"Unsupported filter in roadrecon mode: {filter_query}")
        return match.group(1), match.group(2).replace("''", "'")

    def get_users_by_filter(self, filter_query: str) -> List[Dict]:
        """Query users by userPrincipalName or displayName."""
        field, value = self._parse_eq_filter(filter_query)
        if field not in ('userPrincipalName', 'displayName', 'mail'):
            raise ValueError(f"Unsupported user filter field in roadrecon mode: {field}")
        return [self._user(r) for r in self._user_rows(f'"{field}" = ?', (value,))]

    def get_groups_by_filter(self, filter_query: str) -> List[Dict]:
        """Query groups by displayName."""
        field, value = self._parse_eq_filter(filter_query)
        if field not in ('displayName', 'mail'):
            raise ValueError(f"Unsupported group filter field in roadrecon mode: {field}")
        return [self._group(r) for r in self._group_rows(f'"{field}" = ?', (value,))]

    def get_directory_roles_by_filter(self, filter_query: str) -> List[Dict]:
        """Query activated directory roles by displayName."""
        field, value = self._parse_eq_filter(filter_query)
        if field not in ('displayName', 'roleTemplateId'):
            raise ValueError(f"Unsupported directory role filter field in roadrecon mode: {field}")
        rows = self._query(f'SELECT objectId, displayName, description, roleTemplateId FROM DirectoryRoles '
                           f'WHERE "{field}" = ?', (value,))
        return [{'@odata.type': '#microsoft.graph.directoryRole', 'id': r['objectId'],
                 'displayName': r['displayName'], 'description': r['description'],
                 'roleTemplateId': r['roleTemplateId']} for r in rows]
