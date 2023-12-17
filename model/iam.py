from stix2 import properties 
from stix2.v21 import CustomObservable

ACCOUNT='x-observable-account'
IDENTITY='x-observable-identity'
ACCESS_CONTROL_POLICY='x-observable-access-control-policy'
PROCESS='x-observable-process'


@CustomObservable(ACCOUNT, [
    ('identifier', properties.StringProperty(required=True)),
    ('version', properties.StringProperty(required=False)),
    ('display_name', properties.StringProperty(required=False)),
    ('owner', properties.StringProperty(required=False)),
    ('application', properties.StringProperty(required=True))
], ['identifier','application'])
class Account(object):
    pass

@CustomObservable(IDENTITY, [
    ('identifier', properties.StringProperty(required=True)),
    ('version', properties.StringProperty(required=False)),
    ('display_name', properties.StringProperty(required=False)),
    ('owner', properties.StringProperty(required=False)),
], ['identifier'])
class Identity(object):
    pass

@CustomObservable(ACCESS_CONTROL_POLICY, [
    ('identifier', properties.StringProperty(required=True)),
    ('version', properties.StringProperty(required=False)),
    ('display_name', properties.StringProperty(required=False)),
    ('owner', properties.StringProperty(required=False)),
    ('application', properties.StringProperty(required=False)),
    ('acp_type', properties.EnumProperty(allowed=['permission','role'], required=True))
], ['identifier','application','acp_type'])
class AccessControlPolicy(object):
    pass

@CustomObservable(PROCESS, [
    ('identifier', properties.StringProperty(required=True)),
    ('display_name', properties.StringProperty(required=False)),
], ['identifier'])
class Process(object):
    pass