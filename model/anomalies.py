from stix2 import properties 
from stix2.v21 import CustomObservable

from model.iam import AccessControlPolicy, Account, Identity, Process

ANOMALY_ORPHAN_ACCOUNT='x-observable-anomaly-orphan-account'
ANOMALY_EXCESSIVE_ACCESS='x-observable-anomaly-excessive-access'
ANOMALY_OUTDATED_ASSIGNMENT_RULE='x-observable-anomaly-outdated-assignment-rule'
ANOMALY_LOW_ATTRIBUTE_QUALITY='x-observable-anomaly-low-attribute-quality'
ANOMALY_PRIVACY_LEAK='x-observable-anomaly-privacy-leak'
ANOMALY_PROCESS_ERROR='x-observable-anomaly-process-error'

@CustomObservable(ANOMALY_ORPHAN_ACCOUNT, [
    ('account', properties.ObjectReferenceProperty(valid_types=[Account], required=True)),
    ('identity', properties.ObjectReferenceProperty(valid_types=[Identity], required=False))
])
class OrphanAccountAnomaly(object):
    pass

@CustomObservable(ANOMALY_EXCESSIVE_ACCESS, [
    ('identity', properties.ObjectReferenceProperty(valid_types=[Identity], required=True)),
    ('access_control_policy', properties.ObjectReferenceProperty(valid_types=[AccessControlPolicy], required=True))
])
class ExcessiveAccessAnomaly(object):
    pass

@CustomObservable(ANOMALY_OUTDATED_ASSIGNMENT_RULE, [
    ('access_control_policy', properties.ObjectReferenceProperty(valid_types=[AccessControlPolicy], required=True)),
    ('identity', properties.ObjectReferenceProperty(valid_types=[Identity], required=True)),
    ('assignment_rule', properties.StringProperty(required=True))
])
class OudatedAssignmentRuleAnomaly(object):
    pass

@CustomObservable(ANOMALY_LOW_ATTRIBUTE_QUALITY, [
    ('entity', properties.ObjectReferenceProperty(valid_types=[Account,Identity,AccessControlPolicy], required=True)),
    ('attribute_quality_policy', properties.StringProperty(required=True))
])
class LowAttributeQualityAnomaly(object):
    pass

@CustomObservable(ANOMALY_PRIVACY_LEAK, [
    ('affected_identity', properties.ObjectReferenceProperty(valid_types=[Identity], required=True)),
    ('leaked_attributes', properties.ListProperty(contained=properties.StringProperty, required=True))
])
class PrivacyLeakAnomaly(object):
    pass

@CustomObservable(ANOMALY_PROCESS_ERROR, [
    ('process', properties.ObjectReferenceProperty(valid_types=[Process], required=True)),
    ('entity', properties.ObjectReferenceProperty(valid_types=[Account,Identity,AccessControlPolicy], required=True))
])
class ProcessErrorAnomaly(object):
    pass