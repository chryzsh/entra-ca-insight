"""
Translate roadrecon policy data to the Microsoft Graph shapes used by CA Insight.

roadrecon stores Conditional Access policies (policyType 18) and named locations
(policyType 6) in the Policys table. Their policyDetail column holds JSON in the
legacy AAD Graph format (PascalCase, e.g. Conditions.Users.Include[].Groups).
This module converts that format to the MS Graph conditionalAccessPolicy and
namedLocation objects returned by /beta/identity/conditionalAccess/*.

Field names on the AAD side follow roadrecon's own parser
(roadtools/roadrecon/plugins/policies.py).
"""

# Standard library imports
import base64
import json
import re
import zlib
from typing import Callable, Dict, List, Optional


# AAD policy type numbers in the roadrecon Policys table
POLICY_TYPE_NAMED_LOCATION = 6
POLICY_TYPE_CONDITIONAL_ACCESS = 18
POLICY_TYPE_AUTH_STRENGTH = 44

STATE_MAP = {
    'Enabled': 'enabled',
    'Disabled': 'disabled',
    'Reporting': 'enabledForReportingButNotEnforced',
}

# AAD grant control name -> MS Graph builtInControls values
CONTROL_MAP = {
    'Block': ['block'],
    'Mfa': ['mfa'],
    'RequireCompliantDevice': ['compliantDevice'],
    'RequireDomainJoinedDevice': ['domainJoinedDevice'],
    'RequireApprovedApp': ['approvedApplication'],
    'RequireCompliantApp': ['compliantApplication'],
    'MfaAndChangePassword': ['mfa', 'passwordChange'],
}

# AAD client type -> MS Graph clientAppTypes value
CLIENT_TYPE_MAP = {
    'Browser': 'browser',
    'Native': 'mobileAppsAndDesktopClients',
    'EasSupported': 'exchangeActiveSync',
    'EasUnsupported': 'exchangeActiveSync',
    'OtherLegacy': 'other',
    'LegacySmtp': 'other',
    'LegacyPop': 'other',
    'LegacyImap': 'other',
    'LegacyMapi': 'other',
    'LegacyOffice': 'other',
}

PLATFORM_MAP = {
    'All': 'all',
    'Android': 'android',
    'iOS': 'iOS',
    'Windows': 'windows',
    'WindowsPhone': 'windowsPhone',
    'macOS': 'macOS',
    'Linux': 'linux',
}

# AAD authentication flow -> MS Graph transferMethods value
AUTH_FLOW_MAP = {
    'DeviceCodeFlow': 'deviceCodeFlow',
    'QrCode': 'authenticationTransfer',
}

# Built-in authentication strengths (names as used by roadrecon)
BUILT_IN_AUTH_STRENGTHS = {
    '00000000-0000-0000-0000-000000000002': 'Multifactor authentication',
    '00000000-0000-0000-0000-000000000003': 'Passwordless MFA',
    '00000000-0000-0000-0000-000000000004': 'Phishing-resistant MFA',
}

# Values that MS Graph keeps as-is in include/exclude lists
USER_KEYWORDS = {'All': 'All', 'None': 'None', 'Guests': 'GuestsOrExternalUsers'}

GUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def _lower_first(value: str) -> str:
    """Convert PascalCase to camelCase (InternalGuest -> internalGuest)."""
    return value[:1].lower() + value[1:] if value else value


def _criteria(section: Optional[Dict], side: str) -> List[Dict]:
    """Return the Include or Exclude criteria list of an AAD condition section."""
    if not section:
        return []
    return section.get(side) or []


def _collect(section: Optional[Dict], side: str, key: str) -> List:
    """Collect all values of one criteria key across an Include/Exclude list."""
    values = []
    for crit in _criteria(section, side):
        for value in crit.get(key) or []:
            if value not in values:
                values.append(value)
    return values


def _parse_detail(policy_detail: Optional[str]) -> List[Dict]:
    """Decode the policyDetail column (JSON list of JSON strings)."""
    if not policy_detail:
        return []
    details = []
    for item in json.loads(policy_detail):
        try:
            details.append(json.loads(item) if isinstance(item, str) else item)
        except json.JSONDecodeError:
            continue
    return details


class PolicyTranslator:
    """Converts roadrecon Policys rows to MS Graph Conditional Access objects"""

    def __init__(self, auth_strengths: Dict[str, Dict] = None, warn: Callable[[str], None] = None):
        """Initialize the translator.

        Parameters:
            auth_strengths (Dict[str, Dict]): Custom authentication strength objects keyed by ID
                                              (MS Graph authenticationStrengthPolicy shape)
            warn (Callable[[str], None]): Callback for one-line warnings about unmapped data
        """
        self.auth_strengths = auth_strengths or {}
        self._warn = warn or (lambda msg: print(f"Warning: {msg}"))

    # === Conditional Access policies ===

    def translate_policy(self, object_id: str, display_name: str, policy_detail: str) -> Optional[Dict]:
        """Translate one CA policy row (policyType 18) to a conditionalAccessPolicy object.

        Parameters:
            object_id (str): Policy objectId (used as the MS Graph policy id)
            display_name (str): Policy display name
            policy_detail (str): Raw policyDetail column value

        Returns:
            Optional[Dict]: MS Graph conditionalAccessPolicy object, or None if the row has no detail
        """
        details = _parse_detail(policy_detail)
        if not details:
            self._warn(f"policy {object_id} has no policyDetail, skipped")
            return None
        detail = details[0]
        cond = detail.get('Conditions') or {}

        known_conditions = {'Users', 'Applications', 'ServicePrincipals', 'ClientTypes', 'DevicePlatforms',
                            'Devices', 'Locations', 'SignInRisks', 'UserRisks', 'ServicePrincipalRisks',
                            'InsiderRisks', 'AuthFlows'}
        for key in cond:
            if key not in known_conditions:
                self._warn(f"policy {object_id}: condition '{key}' has no MS Graph mapping, ignored")

        state = detail.get('State')
        if state not in STATE_MAP:
            self._warn(f"policy {object_id}: unknown state '{state}', treated as disabled")

        return {
            'id': object_id,
            'templateId': detail.get('TemplateId'),
            'displayName': display_name,
            'createdDateTime': detail.get('CreatedDateTime'),
            'modifiedDateTime': detail.get('ModifiedDateTime'),
            'state': STATE_MAP.get(state, 'disabled'),
            'conditions': {
                'users': self._translate_users(cond.get('Users'), object_id),
                'applications': self._translate_applications(cond.get('Applications'), object_id),
                'clientApplications': self._translate_client_applications(cond.get('ServicePrincipals'), object_id),
                'clientAppTypes': self._translate_client_types(cond.get('ClientTypes'), object_id),
                'platforms': self._translate_platforms(cond.get('DevicePlatforms')),
                'locations': self._translate_locations(cond.get('Locations')),
                'devices': self._translate_devices(cond.get('Devices'), object_id),
                'userRiskLevels': self._translate_risks(cond.get('UserRisks'), 'UserRisks'),
                'signInRiskLevels': self._translate_risks(cond.get('SignInRisks'), 'SignInRisks'),
                'servicePrincipalRiskLevels': self._translate_risks(cond.get('ServicePrincipalRisks'), 'ServicePrincipalRisks'),
                'insiderRiskLevels': ','.join(self._translate_risks(cond.get('InsiderRisks'), 'InsiderRisks')) or None,
                'authenticationFlows': self._translate_auth_flows(cond.get('AuthFlows'), object_id),
                'times': None,
            },
            'grantControls': self._translate_grant_controls(detail, object_id),
            'sessionControls': self._translate_session_controls(detail, object_id),
        }

    def _translate_users(self, users: Optional[Dict], object_id: str) -> Dict:
        """Map Conditions.Users to conditions.users."""
        result = {
            'includeUsers': [], 'excludeUsers': [],
            'includeGroups': [], 'excludeGroups': [],
            'includeRoles': [], 'excludeRoles': [],
            'includeGuestsOrExternalUsers': None, 'excludeGuestsOrExternalUsers': None,
        }
        for side, prefix in (('Include', 'include'), ('Exclude', 'exclude')):
            for crit in _criteria(users, side):
                for key, value in crit.items():
                    if key == 'Users':
                        for uid in value:
                            mapped = USER_KEYWORDS.get(uid, uid)
                            if mapped not in result[f'{prefix}Users']:
                                result[f'{prefix}Users'].append(mapped)
                    elif key == 'Groups':
                        result[f'{prefix}Groups'].extend(g for g in value if g not in result[f'{prefix}Groups'])
                    elif key == 'Roles':
                        result[f'{prefix}Roles'].extend(r for r in value if r not in result[f'{prefix}Roles'])
                    elif key == 'GuestsOrExternalUsers':
                        result[f'{prefix}GuestsOrExternalUsers'] = self._translate_guests(value)
                    else:
                        self._warn(f"policy {object_id}: users criterion '{key}' has no MS Graph mapping, ignored")
        return result

    @staticmethod
    def _translate_guests(value: Dict) -> Dict:
        """Map a GuestsOrExternalUsers criterion to conditionalAccessGuestsOrExternalUsers."""
        types = [t.strip() for t in (value.get('GuestOrExternalUserTypes') or '').split(',') if t.strip()]
        tenants = value.get('ExternalTenants')
        if tenants:
            external_tenants = {
                '@odata.type': '#microsoft.graph.conditionalAccessEnumeratedExternalTenants',
                'membershipKind': 'enumerated',
                'members': list(tenants),
            }
        else:
            external_tenants = {
                '@odata.type': '#microsoft.graph.conditionalAccessAllExternalTenants',
                'membershipKind': 'all',
            }
        return {
            'guestOrExternalUserTypes': ','.join(_lower_first(t) for t in types),
            'externalTenants': external_tenants,
        }

    def _translate_applications(self, apps: Optional[Dict], object_id: str) -> Dict:
        """Map Conditions.Applications to conditions.applications.

        AAD stores user actions and authentication contexts in the same Acrs list.
        User actions start with 'urn:user:', everything else is an auth context ID.
        """
        result = {
            'includeApplications': [], 'excludeApplications': [],
            'includeUserActions': [], 'includeAuthenticationContextClassReferences': [],
            'applicationFilter': None,
        }
        for side, prefix in (('Include', 'include'), ('Exclude', 'exclude')):
            for crit in _criteria(apps, side):
                for key, value in crit.items():
                    if key == 'Applications':
                        target = result[f'{prefix}Applications']
                        target.extend(a for a in value if a not in target)
                    elif key == 'Acrs' and side == 'Include':
                        for acr in value:
                            if acr.lower().startswith('urn:user:'):
                                result['includeUserActions'].append(acr.lower())
                            else:
                                result['includeAuthenticationContextClassReferences'].append(acr)
                    else:
                        self._warn(f"policy {object_id}: applications criterion '{side}.{key}' has no MS Graph mapping, ignored")
        return result

    def _translate_client_applications(self, sps: Optional[Dict], object_id: str) -> Dict:
        """Map Conditions.ServicePrincipals to conditions.clientApplications."""
        result = {
            'includeServicePrincipals': [], 'excludeServicePrincipals': [],
            'includeAgentIdServicePrincipals': [], 'excludeAgentIdServicePrincipals': [],
            'servicePrincipalFilter': None,
        }
        for side, prefix in (('Include', 'include'), ('Exclude', 'exclude')):
            for crit in _criteria(sps, side):
                agentic = bool(crit.get('IsAgentic'))
                for key, value in crit.items():
                    if key == 'IsAgentic':
                        continue
                    if key == 'ServicePrincipals':
                        if agentic:
                            self._warn(f"policy {object_id}: agentic service principal criterion mapped to {prefix}AgentIdServicePrincipals (unverified)")
                            field = f'{prefix}AgentIdServicePrincipals'
                        else:
                            field = f'{prefix}ServicePrincipals'
                        result[field].extend(sp for sp in value if sp not in result[field])
                    elif key == 'ServicePrincipalFilterRule':
                        rule = ' '.join(value) if isinstance(value, list) else value
                        result['servicePrincipalFilter'] = {'mode': prefix, 'rule': rule}
                    else:
                        self._warn(f"policy {object_id}: service principal criterion '{key}' has no MS Graph mapping, ignored")
        return result

    def _translate_client_types(self, client_types: Optional[Dict], object_id: str) -> List[str]:
        """Map Conditions.ClientTypes to conditions.clientAppTypes (default: ['all'])."""
        values = _collect(client_types, 'Include', 'ClientTypes')
        if not values:
            return ['all']
        result = []
        for value in values:
            mapped = CLIENT_TYPE_MAP.get(value)
            if not mapped:
                self._warn(f"policy {object_id}: unknown client type '{value}', mapped to 'other'")
                mapped = 'other'
            if mapped not in result:
                result.append(mapped)
        return result

    @staticmethod
    def _translate_platforms(platforms: Optional[Dict]) -> Optional[Dict]:
        """Map Conditions.DevicePlatforms to conditions.platforms."""
        if not platforms:
            return None
        return {
            'includePlatforms': [PLATFORM_MAP.get(p, _lower_first(p)) for p in _collect(platforms, 'Include', 'DevicePlatforms')],
            'excludePlatforms': [PLATFORM_MAP.get(p, _lower_first(p)) for p in _collect(platforms, 'Exclude', 'DevicePlatforms')],
        }

    @staticmethod
    def _translate_locations(locations: Optional[Dict]) -> Optional[Dict]:
        """Map Conditions.Locations to conditions.locations."""
        if not locations:
            return None
        return {
            'includeLocations': _collect(locations, 'Include', 'Locations'),
            'excludeLocations': _collect(locations, 'Exclude', 'Locations'),
        }

    def _translate_devices(self, devices: Optional[Dict], object_id: str) -> Optional[Dict]:
        """Map Conditions.Devices to conditions.devices.

        AAD expresses an exclude-mode device filter as Include DeviceRule 'All' plus
        an Exclude DeviceRule. An include-mode filter is an Include DeviceRule other than 'All'.
        """
        if not devices:
            return None
        include_rules = [c['DeviceRule'] for c in _criteria(devices, 'Include') if c.get('DeviceRule')]
        exclude_rules = [c['DeviceRule'] for c in _criteria(devices, 'Exclude') if c.get('DeviceRule')]
        include_rules = [r for r in include_rules if r != 'All']

        device_filter = None
        if include_rules:
            device_filter = {'mode': 'include', 'rule': include_rules[0]}
        elif exclude_rules:
            device_filter = {'mode': 'exclude', 'rule': exclude_rules[0]}
        if len(include_rules) + len(exclude_rules) > 1:
            self._warn(f"policy {object_id}: more than one device rule, only the first is used")

        return {
            'includeDeviceStates': _collect(devices, 'Include', 'DeviceStates'),
            'excludeDeviceStates': _collect(devices, 'Exclude', 'DeviceStates'),
            'deviceFilter': device_filter,
        }

    @staticmethod
    def _translate_risks(risks: Optional[Dict], key: str) -> List[str]:
        """Map a risk condition (SignInRisks, UserRisks, ...) to a list of lowercase levels."""
        return [r.lower() for r in _collect(risks, 'Include', key)]

    def _translate_auth_flows(self, auth_flows: Optional[Dict], object_id: str) -> Optional[Dict]:
        """Map Conditions.AuthFlows to conditions.authenticationFlows.

        AAD stores the flows as one comma-separated string, e.g. 'DeviceCodeFlow, QrCode'.
        MS Graph returns transferMethods as a comma-separated string as well.
        """
        if not auth_flows:
            return None
        methods = []
        for value in _collect(auth_flows, 'Include', 'AuthFlows'):
            for flow in str(value).split(','):
                flow = flow.strip()
                if not flow:
                    continue
                mapped = AUTH_FLOW_MAP.get(flow)
                if not mapped:
                    self._warn(f"policy {object_id}: unknown auth flow '{flow}', kept as-is")
                    mapped = _lower_first(flow)
                if mapped not in methods:
                    methods.append(mapped)
        return {'transferMethods': ','.join(methods)} if methods else None

    def _translate_grant_controls(self, detail: Dict, object_id: str) -> Optional[Dict]:
        """Map Controls to grantControls.

        Each entry in the AAD Controls list is one requirement. Several entries must
        all be met (AND). Several controls inside one entry are alternatives (OR).
        GUID values in a Control list are terms of use agreements.
        """
        entries = detail.get('Controls') or []
        if not entries:
            return None

        built_in = []
        terms_of_use = []
        auth_strength = None
        operator = 'AND' if len(entries) > 1 else 'OR'

        for entry in entries:
            for key in entry:
                if key not in ('Control', 'AuthStrengthIds'):
                    self._warn(f"policy {object_id}: grant control '{key}' has no MS Graph mapping, ignored")
            for control in entry.get('Control') or []:
                if GUID_RE.match(control):
                    terms_of_use.append(control)
                    continue
                mapped = CONTROL_MAP.get(control)
                if not mapped:
                    self._warn(f"policy {object_id}: unknown grant control '{control}', kept as-is")
                    mapped = [_lower_first(control)]
                if control == 'MfaAndChangePassword':
                    operator = 'AND'
                built_in.extend(c for c in mapped if c not in built_in)
            strength_ids = entry.get('AuthStrengthIds') or []
            if len(strength_ids) > 1:
                self._warn(f"policy {object_id}: more than one authentication strength, only the first is used")
            if strength_ids and not auth_strength:
                auth_strength = self._auth_strength(strength_ids[0])

        return {
            'operator': operator,
            'builtInControls': built_in,
            'customAuthenticationFactors': [],
            'termsOfUse': terms_of_use,
            'authenticationStrength': auth_strength,
        }

    def _auth_strength(self, strength_id: str) -> Dict:
        """Build an authenticationStrengthPolicy object for a strength ID."""
        if strength_id in BUILT_IN_AUTH_STRENGTHS:
            return {
                'id': strength_id,
                'displayName': BUILT_IN_AUTH_STRENGTHS[strength_id],
                'policyType': 'builtIn',
            }
        if strength_id in self.auth_strengths:
            return self.auth_strengths[strength_id]
        self._warn(f"authentication strength {strength_id} not found in database")
        return {'id': strength_id, 'displayName': strength_id, 'policyType': 'custom'}

    def _translate_session_controls(self, detail: Dict, object_id: str) -> Optional[Dict]:
        """Map SessionControls and their top-level settings to sessionControls."""
        controls = detail.get('SessionControls') or []
        if not controls:
            return None

        result = {
            'disableResilienceDefaults': None,
            'applicationEnforcedRestrictions': None,
            'cloudAppSecurity': None,
            'persistentBrowser': None,
            'continuousAccessEvaluation': None,
            'secureSignInSession': None,
            'signInFrequency': None,
        }
        for control in controls:
            if control == 'SignInFrequency':
                result['signInFrequency'] = self._sign_in_frequency(detail, object_id)
            elif control == 'PersistentBrowserSessionMode':
                mode = detail.get('PersistentBrowserSessionMode')
                result['persistentBrowser'] = {'isEnabled': True, 'mode': _lower_first(mode) if mode else None}
            elif control == 'AppEnforcedRestrictions':
                result['applicationEnforcedRestrictions'] = {'isEnabled': True}
            elif control == 'CloudAppSecurity':
                # The CasSessionControlType number has no verified mapping to the MS Graph enum
                cas_type = detail.get('CasSessionControlType')
                result['cloudAppSecurity'] = {
                    'isEnabled': True,
                    'cloudAppSecurityType': f"unmapped (CasSessionControlType={cas_type})",
                }
            elif control == 'ContinuousAccessEvaluation':
                mode = detail.get('ContinuousAccessEvaluationMode')
                result['continuousAccessEvaluation'] = {'mode': _lower_first(mode) if mode else None}
            elif control == 'DisableResilienceDefaults':
                result['disableResilienceDefaults'] = True
            elif control == 'SecureSignInSession':
                result['secureSignInSession'] = {'isEnabled': True}
            else:
                self._warn(f"policy {object_id}: session control '{control}' has no MS Graph mapping, ignored")
        return result

    def _sign_in_frequency(self, detail: Dict, object_id: str) -> Dict:
        """Build a signInFrequencySessionControl from SignInFrequencyType/TimeSpan.

        SignInFrequencyType 10 is a fixed interval (TimeSpan 'd.hh:mm:ss' or 'hh:mm:ss'),
        30 is 'every time'. The authentication type is not stored in PolicyDetail.
        """
        freq_type = detail.get('SignInFrequencyType')
        if freq_type == 30:
            return {'isEnabled': True, 'value': None, 'type': None,
                    'authenticationType': None, 'frequencyInterval': 'everyTime'}
        if freq_type == 10:
            span = detail.get('SignInFrequencyTimeSpan') or ''
            match = re.match(r'^(?:(\d+)\.)?(\d+):(\d+):(\d+)$', span)
            if match:
                days = int(match.group(1) or 0)
                hours = int(match.group(2))
                if days and not hours:
                    value, unit = days, 'days'
                else:
                    value, unit = days * 24 + hours, 'hours'
                return {'isEnabled': True, 'value': value, 'type': unit,
                        'authenticationType': None, 'frequencyInterval': 'timeBased'}
        self._warn(f"policy {object_id}: sign-in frequency setting could not be parsed")
        return {'isEnabled': True, 'value': None, 'type': None,
                'authenticationType': None, 'frequencyInterval': None}

    # === Named locations ===

    def translate_named_locations(self, object_id: str, display_name: str, policy_identifier: str,
                                  policy_detail: str) -> List[Dict]:
        """Translate one named location row (policyType 6) to namedLocation objects.

        New-format rows hold one location; the location ID referenced by CA policies is
        the policyIdentifier. Legacy rows hold KnownNetworkPolicies entries that each
        carry their own NetworkId and NetworkName.

        Returns:
            List[Dict]: MS Graph ipNamedLocation / countryNamedLocation objects
        """
        details = _parse_detail(policy_detail)
        legacy = [d['KnownNetworkPolicies'] for d in details if d.get('KnownNetworkPolicies')]
        if legacy:
            return [self._named_location(d.get('NetworkId'), (d.get('NetworkName') or '').strip(), d)
                    for d in legacy]
        if not details:
            return []
        return [self._named_location(policy_identifier or object_id, display_name, details[0])]

    def _named_location(self, location_id: str, display_name: str, detail: Dict) -> Dict:
        """Build an ipNamedLocation or countryNamedLocation object."""
        base = {
            'id': location_id,
            'displayName': display_name,
            'createdDateTime': detail.get('CreatedDateTime'),
            'modifiedDateTime': detail.get('ModifiedDateTime'),
        }
        countries = detail.get('CountryIsoCodes')
        if countries:
            lookup = detail.get('CountryLookupMethod')
            base.update({
                '@odata.type': '#microsoft.graph.countryNamedLocation',
                'countriesAndRegions': list(countries),
                'includeUnknownCountriesAndRegions': bool(detail.get('ApplyToUnknownCountry')),
                'countryLookupMethod': {0: 'clientIpAddress', 1: 'authenticatorAppGps'}.get(lookup, lookup),
            })
            return base

        cidrs = list(detail.get('CidrIpRanges') or [])
        compressed = detail.get('CompressedCidrIpRanges')
        if compressed:
            try:
                raw = zlib.decompress(base64.b64decode(compressed), -zlib.MAX_WBITS).decode()
                cidrs.extend(c.strip() for c in raw.split(',') if c.strip())
            except (ValueError, zlib.error) as e:
                self._warn(f"named location {location_id}: could not decode IP ranges: {e}")
        base.update({
            '@odata.type': '#microsoft.graph.ipNamedLocation',
            'isTrusted': 'trusted' in (detail.get('Categories') or []),
            'ipRanges': [
                {'@odata.type': '#microsoft.graph.iPv6CidrRange' if ':' in c else '#microsoft.graph.iPv4CidrRange',
                 'cidrAddress': c}
                for c in cidrs
            ],
        })
        return base

    # === Authentication strengths ===

    @staticmethod
    def translate_auth_strength(object_id: str, display_name: str, policy_identifier: str,
                                policy_detail: str) -> Optional[Dict]:
        """Translate a custom authentication strength row (policyType 44)."""
        details = _parse_detail(policy_detail)
        detail = details[0] if details else {}
        return {
            'id': policy_identifier or object_id,
            'displayName': display_name,
            'description': detail.get('description'),
            'policyType': 'custom',
            'requirementsSatisfied': _lower_first(detail.get('requirementsSatisfied') or '') or None,
            # Kept in the AAD format, not converted to MS Graph combination names
            'allowedCombinations': detail.get('allowedCombinations') or [],
        }
